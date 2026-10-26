package systemauth_test

import (
	"context"
	"testing"

	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// TestRotateClientSecretBackends runs two rotations on each Ent backend
// and checks that N and N-1 authenticate and N-2 does not.
func TestRotateClientSecretBackends(t *testing.T) {
	for _, b := range entBackends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			ctx := context.Background()
			owner, err := db.Principal.Create().SetType(principal.TypeService).SetIdentifier("owner").
				SetDisplayName("Owner").Save(ctx)
			if err != nil {
				t.Fatal(err)
			}
			st := systemauth.NewEntStorage(db, systemauth.WithDefaultOwner(owner.ID))
			c, err := systemauth.NewClientFromConfig(systemauth.ClientConfig{
				ID: "web", Type: "confidential", Name: "Web", Secret: "s0",
				RedirectURIs: []string{"https://app.example.com/callback"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := st.CreateClient(ctx, c); err != nil {
				t.Fatal(err)
			}
			r1, err := st.RotateClientSecret(ctx, "web")
			if err != nil {
				t.Fatal(err)
			}
			r2, err := st.RotateClientSecret(ctx, "web")
			if err != nil {
				t.Fatal(err)
			}
			for s, want := range map[string]bool{"s0": false, r1.Secret: true, r2.Secret: true} {
				if got := accepts(ctx, t, st, s); got != want {
					t.Errorf("%q accepted=%v, want %v", s, got, want)
				}
			}
		})
	}
}

func accepts(ctx context.Context, t *testing.T, st *systemauth.EntStorage, secret string) bool {
	t.Helper()
	fc, err := st.GetClient(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	rc, ok := fc.(fosite.ClientWithSecretRotation)
	if !ok {
		t.Fatal("client does not support secret rotation")
	}
	h := systemauth.ClientSecretHasher{}
	for _, hash := range append([][]byte{rc.GetHashedSecret()}, rc.GetRotatedHashes()...) {
		if h.Compare(ctx, hash, []byte(secret)) == nil {
			return true
		}
	}
	return false
}
