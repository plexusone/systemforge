package systemauthsvc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/console"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// mountConsole serves the organization console (ADR-018) when the
// configuration enables it: signed in with the SystemAuth login session,
// listing the person's organizations from the orgs claim, and with the
// connections section when connections are enabled.
func (s *Service) mountConsole(c *Config) error {
	if c.Console == nil {
		return nil
	}
	con, err := console.New(console.Options{
		Principal:     s.consolePrincipal,
		Organizations: s.consoleOrganizations,
		ReturnTo:      s.server.ValidateReturnTo,
		SignOut:       s.server.EndLoginSession,
		Apps:          s.consoleApps,
		Connections:   s.conns,
		WebDir:        c.Console.WebDir,
		LoginPath:     systemauth.LoginPath,
		Logger:        s.logger,
	})
	if err != nil {
		return fmt.Errorf("systemauthsvc: %w", err)
	}
	s.console = con
	router := s.server.Router()
	router.Handle(console.Prefix, con)
	router.Handle(console.Prefix+"/*", con)
	s.logger.Info("console enabled", "web_dir", c.Console.WebDir, "connections", s.conns != nil)
	return nil
}

// closeConsole releases the console's built pages.
func (s *Service) closeConsole() error {
	if s.console == nil {
		return nil
	}
	con := s.console
	s.console = nil
	return con.Close()
}

func (s *Service) consolePrincipal(r *http.Request) (uuid.UUID, error) {
	sess, err := s.server.CurrentLoginSession(r)
	if errors.Is(err, systemauth.ErrLoginSessionNotFound) {
		return uuid.Nil, console.ErrNoSession
	}
	if err != nil {
		return uuid.Nil, err
	}
	return sess.PrincipalID, nil
}

func (s *Service) consoleOrganizations(ctx context.Context, principal uuid.UUID) ([]console.Organization, error) {
	res, err := s.server.OrgsClaim(ctx, principal, false)
	if err != nil {
		return nil, err
	}
	out := make([]console.Organization, 0, len(res.Orgs))
	for _, o := range res.Orgs {
		out = append(out, console.Organization{ID: o.ID, Slug: o.Slug, Name: o.Name, Type: o.Type, Role: o.Role, Apps: o.Apps})
	}
	return out, nil
}

func (s *Service) consoleApps(context.Context) ([]console.App, error) {
	apps := s.apps.Apps()
	out := make([]console.App, 0, len(apps))
	for _, a := range apps {
		out = append(out, console.App{ID: a.ID, Name: a.Name, URL: a.URL, Icon: a.Icon, Order: a.Order})
	}
	return out, nil
}
