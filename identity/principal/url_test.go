package principal_test

import (
	"context"
	"errors"
	"testing"

	"github.com/plexusone/systemforge/identity/principal"
)

func TestAvatarsAndLogosMustBeHTTPS(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(t)
	str := func(s string) *string { return &s }

	h, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim", AvatarURL: str("javascript:alert(1)")})
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if h.Human.AvatarURL != nil {
		t.Errorf("avatar = %q, want none stored", *h.Human.AvatarURL)
	}
	h, err = svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{AvatarURL: str("https://avatars.example.com/k.png")})
	if err != nil {
		t.Fatalf("UpdateHuman: %v", err)
	}
	if h.Human.AvatarURL == nil || *h.Human.AvatarURL != "https://avatars.example.com/k.png" {
		t.Errorf("avatar = %v, want the https URL", h.Human.AvatarURL)
	}
	h, err = svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{AvatarURL: str("http://avatars.example.com/k.png")})
	if err != nil {
		t.Fatalf("UpdateHuman: %v", err)
	}
	if h.Human.AvatarURL != nil && *h.Human.AvatarURL != "" {
		t.Errorf("avatar = %q, want it cleared", *h.Human.AvatarURL)
	}

	if _, err := svc.CreateApplication(ctx, principal.CreateApplicationInput{ClientID: "app", DisplayName: "App", LogoURL: str("data:image/png;base64,AA")}); !errors.Is(err, principal.ErrInvalidURL) {
		t.Errorf("CreateApplication: %v, want ErrInvalidURL", err)
	}
}
