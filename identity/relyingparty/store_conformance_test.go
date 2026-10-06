package relyingparty_test

import (
	"testing"

	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/relyingparty/storetest"
)

func TestMemorySessionStoreConformance(t *testing.T) {
	storetest.SessionStore(t, func(*testing.T) relyingparty.SessionStore {
		return relyingparty.NewMemorySessionStore()
	})
}

func TestMemoryLoginStateStoreConformance(t *testing.T) {
	storetest.LoginStateStore(t, func(*testing.T) relyingparty.LoginStateStore {
		return relyingparty.NewMemoryLoginStateStore()
	})
}
