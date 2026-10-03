package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// Handler manages OAuth2 authentication flows.
type Handler struct {
	providers  map[Provider]*ProviderConfig
	stateStore StateStore
}

// StateStore persists OAuth state for CSRF protection.
type StateStore interface {
	// Set stores a state value with expiration.
	Set(ctx context.Context, state string, data StateData, expiry time.Duration) error

	// Get retrieves and deletes a state value.
	Get(ctx context.Context, state string) (StateData, error)
}

// StateData holds data associated with an OAuth state.
type StateData struct {
	Provider    Provider `json:"provider"`
	RedirectURL string   `json:"redirect_url,omitempty"`
	Nonce       string   `json:"nonce,omitempty"`
}

// MemoryStateStore is a simple in-memory state store for development.
// Use a Redis or database-backed store in production.
type MemoryStateStore struct {
	states map[string]stateEntry
}

type stateEntry struct {
	data   StateData
	expiry time.Time
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		states: make(map[string]stateEntry),
	}
}

// Set stores a state value.
func (s *MemoryStateStore) Set(ctx context.Context, state string, data StateData, expiry time.Duration) error {
	s.states[state] = stateEntry{
		data:   data,
		expiry: time.Now().Add(expiry),
	}
	return nil
}

// Get retrieves and deletes a state value.
func (s *MemoryStateStore) Get(ctx context.Context, state string) (StateData, error) {
	entry, ok := s.states[state]
	if !ok {
		return StateData{}, errors.New("state not found")
	}

	delete(s.states, state)

	if time.Now().After(entry.expiry) {
		return StateData{}, errors.New("state expired")
	}

	return entry.data, nil
}

// NewHandler creates a new OAuth handler.
func NewHandler(stateStore StateStore) *Handler {
	if stateStore == nil {
		stateStore = NewMemoryStateStore()
	}
	return &Handler{
		providers:  make(map[Provider]*ProviderConfig),
		stateStore: stateStore,
	}
}

// RegisterProvider adds an OAuth provider configuration.
func (h *Handler) RegisterProvider(cfg *ProviderConfig) {
	h.providers[cfg.Provider] = cfg
}

// GetProvider returns the configuration for a provider.
func (h *Handler) GetProvider(provider Provider) (*ProviderConfig, bool) {
	cfg, ok := h.providers[provider]
	return cfg, ok
}

var (
	// ErrProviderNotConfigured is returned when a provider is not configured.
	ErrProviderNotConfigured = errors.New("oauth provider not configured")
	// ErrInvalidState is returned when the OAuth state is invalid.
	ErrInvalidState = errors.New("invalid oauth state")
	// ErrFailedUserInfo is returned when user info cannot be fetched.
	ErrFailedUserInfo = errors.New("failed to fetch user info")
)

// AuthorizationURL generates an OAuth authorization URL.
func (h *Handler) AuthorizationURL(ctx context.Context, provider Provider, redirectURL string) (string, error) {
	cfg, ok := h.providers[provider]
	if !ok {
		return "", ErrProviderNotConfigured
	}

	state, err := generateState()
	if err != nil {
		return "", fmt.Errorf("generating state: %w", err)
	}

	stateData := StateData{
		Provider:    provider,
		RedirectURL: redirectURL,
	}

	if err := h.stateStore.Set(ctx, state, stateData, 10*time.Minute); err != nil {
		return "", fmt.Errorf("storing state: %w", err)
	}

	oauth2Cfg := cfg.OAuth2Config()
	return oauth2Cfg.AuthCodeURL(state), nil
}

// HandleCallback processes the OAuth callback and returns user information.
func (h *Handler) HandleCallback(ctx context.Context, provider Provider, code, state string) (*UserInfo, string, error) {
	stateData, err := h.stateStore.Get(ctx, state)
	if err != nil {
		return nil, "", ErrInvalidState
	}

	if stateData.Provider != provider {
		return nil, "", ErrInvalidState
	}

	cfg, ok := h.providers[provider]
	if !ok {
		return nil, "", ErrProviderNotConfigured
	}

	oauth2Cfg := cfg.OAuth2Config()
	token, err := oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		return nil, "", fmt.Errorf("exchanging code: %w", err)
	}

	userInfo, err := h.fetchUserInfo(ctx, provider, token)
	if err != nil {
		return nil, "", err
	}

	return userInfo, stateData.RedirectURL, nil
}

// fetchUserInfo fetches user information from the OAuth provider.
func (h *Handler) fetchUserInfo(ctx context.Context, provider Provider, token *oauth2.Token) (*UserInfo, error) {
	switch provider {
	case GitHub:
		return h.fetchGitHubUser(ctx, token)
	case Google:
		return h.fetchGoogleUser(ctx, token)
	default:
		return nil, ErrProviderNotConfigured
	}
}

func (h *Handler) fetchGitHubUser(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req) //nolint:gosec // G704: hardcoded GitHub API URL, not user input
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedUserInfo, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", ErrFailedUserInfo, resp.StatusCode, body)
	}

	var user GitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedUserInfo, err)
	}

	// Fetch primary email if not in profile
	if user.Email == "" {
		email, err := h.fetchGitHubEmail(ctx, token)
		if err == nil {
			user.Email = email
		}
	}

	return user.ToUserInfo(token.AccessToken, token.RefreshToken), nil
}

func (h *Handler) fetchGitHubEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req) //nolint:gosec // G704: hardcoded GitHub API URL, not user input
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch emails: status %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	return "", errors.New("no primary verified email found")
}

func (h *Handler) fetchGoogleUser(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := client.Do(req) //nolint:gosec // G704: hardcoded Google API URL, not user input
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedUserInfo, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d: %s", ErrFailedUserInfo, resp.StatusCode, body)
	}

	var user GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedUserInfo, err)
	}

	return user.ToUserInfo(token.AccessToken, token.RefreshToken), nil
}

// generateState generates a cryptographically random state string.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
