package marketplace

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

type entService struct {
	listings *EntListingService
	licenses *EntLicenseService
	checkout CheckoutService
}

func (s entService) Listings() ListingService           { return s.listings }
func (s entService) Licenses() LicenseService           { return s.licenses }
func (s entService) Subscriptions() SubscriptionService { return nil }
func (s entService) Checkout() CheckoutService          { return s.checkout }

// accessFixture is a seller organization with an owner, admin, and
// member; a buyer organization with an admin and member; and an outsider.
type accessFixture struct {
	t        *testing.T
	db       *ent.Client
	api      humatest.TestAPI
	checkout *fakeCheckout
	seller   uuid.UUID
	buyer    uuid.UUID
	who      map[string]uuid.UUID
}

func newAccessFixture(t *testing.T, opts ...APIOption) *accessFixture {
	t.Helper()
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	f := &accessFixture{t: t, db: db, checkout: &fakeCheckout{}, who: map[string]uuid.UUID{}}
	for _, org := range []*uuid.UUID{&f.seller, &f.buyer} {
		o, err := db.Organization.Create().SetName("Org").SetSlug("org-" + uuid.NewString()[:8]).Save(ctx)
		if err != nil {
			t.Fatalf("organization: %v", err)
		}
		*org = o.ID
	}
	roles := map[[2]uuid.UUID]string{}
	for name, membership := range map[string]struct {
		org  uuid.UUID
		role string
	}{
		"seller-owner":  {f.seller, "owner"},
		"seller-admin":  {f.seller, "admin"},
		"seller-member": {f.seller, "member"},
		"buyer-admin":   {f.buyer, "admin"},
		"buyer-member":  {f.buyer, "member"},
		"outsider":      {},
	} {
		p, err := db.Principal.Create().SetType("human").SetIdentifier(name + "@example.com").SetDisplayName(name).Save(ctx)
		if err != nil {
			t.Fatalf("principal: %v", err)
		}
		f.who[name] = p.ID
		if membership.role != "" {
			roles[[2]uuid.UUID{p.ID, membership.org}] = membership.role
		}
	}
	authorizer := rbac.New(rbac.WithRoleGetter(func(_ context.Context, pid, oid uuid.UUID) (string, error) {
		return roles[[2]uuid.UUID{pid, oid}], nil
	}))

	_, api := humatest.New(t)
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		if id := ctx.Header(principalHeader); id != "" {
			ctx = huma.WithContext(ctx, requestprincipal.WithPrincipal(ctx.Context(), &requestprincipal.RequestPrincipal{PrincipalID: id}))
		}
		next(ctx)
	})
	svc := entService{listings: NewEntListingService(db, nil), licenses: NewEntLicenseService(db, nil), checkout: f.checkout}
	NewAPI(api, APIConfig{}, svc, append([]APIOption{WithAuthorizer(authorizer)}, opts...)...)
	f.api = api
	return f
}

// do sends a request as the named principal ("" for anonymous).
func (f *accessFixture) do(method, path, who string, body ...any) *httpResult {
	f.t.Helper()
	args := []any{}
	if who != "" {
		args = append(args, principalHeader+": "+f.who[who].String())
	}
	args = append(args, body...)
	resp := f.api.Do(method, path, args...)
	return &httpResult{code: resp.Code, body: resp.Body.Bytes()}
}

type httpResult struct {
	code int
	body []byte
}

func (f *accessFixture) createListing(who string) string {
	f.t.Helper()
	r := f.do(http.MethodPost, "/listings", who, map[string]any{
		"creator_org_id": f.seller.String(), "product_type": "course", "title": "Course",
		"pricing_model": "one_time", "price_cents": 1000, "currency": "USD",
	})
	if r.code != http.StatusOK && r.code != http.StatusCreated {
		f.t.Fatalf("create listing as %s: %d %s", who, r.code, r.body)
	}
	var out ListingResponse
	if err := json.Unmarshal(r.body, &out); err != nil {
		f.t.Fatalf("decode listing: %v", err)
	}
	if out.OwnerID != f.who[who].String() {
		f.t.Errorf("owner = %s, want caller %s", out.OwnerID, who)
	}
	return out.ID
}

func TestListingAccess(t *testing.T) {
	f := newAccessFixture(t)
	body := func(extra map[string]any) map[string]any {
		b := map[string]any{"creator_org_id": f.seller.String(), "product_type": "course", "title": "Course",
			"pricing_model": "one_time", "price_cents": 1000, "currency": "USD"}
		for k, v := range extra {
			b[k] = v
		}
		return b
	}

	// Create: admins and above, as themselves.
	id := f.createListing("seller-admin")
	for who, want := range map[string]int{
		"":              http.StatusUnauthorized,
		"seller-member": http.StatusForbidden,
		"outsider":      http.StatusForbidden,
	} {
		if r := f.do(http.MethodPost, "/listings", who, body(nil)); r.code != want {
			t.Errorf("create as %q: %d, want %d", who, r.code, want)
		}
	}
	if r := f.do(http.MethodPost, "/listings", "seller-owner", body(map[string]any{"owner_id": f.who["seller-admin"].String()})); r.code != http.StatusForbidden {
		t.Errorf("create for someone else: %d", r.code)
	}

	// A draft is invisible outside the seller organization.
	for who, want := range map[string]int{"seller-member": 200, "": 404, "outsider": 404, "buyer-admin": 404} {
		if r := f.do(http.MethodGet, "/listings/"+id, who); r.code != want {
			t.Errorf("get draft as %q: %d, want %d", who, r.code, want)
		}
	}
	listed := func(query, who string) int {
		r := f.do(http.MethodGet, "/listings"+query, who)
		if r.code != http.StatusOK {
			t.Fatalf("list %s as %q: %d %s", query, who, r.code, r.body)
		}
		var out struct {
			Listings []ListingResponse `json:"listings"`
		}
		if err := json.Unmarshal(r.body, &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return len(out.Listings)
	}
	orgQuery := "?creator_org_id=" + f.seller.String()
	if n := listed(orgQuery, "seller-member"); n != 1 {
		t.Errorf("seller member sees %d drafts, want 1", n)
	}
	for _, who := range []string{"", "outsider"} {
		if n := listed(orgQuery, who); n != 0 {
			t.Errorf("%q sees %d drafts", who, n)
		}
		if n := listed(orgQuery+"&status=draft", who); n != 0 {
			t.Errorf("%q sees %d drafts filtering by status", who, n)
		}
	}

	// Update and publish: admins and owners; archive and delete likewise.
	patch := map[string]any{"title": "Renamed"}
	for who, want := range map[string]int{"seller-member": 403, "outsider": 403, "": 401, "seller-admin": 200} {
		if r := f.do(http.MethodPatch, "/listings/"+id, who, patch); r.code != want {
			t.Errorf("update as %q: %d, want %d", who, r.code, want)
		}
	}
	if r := f.do(http.MethodPost, "/listings/"+id+"/publish", "seller-member"); r.code != http.StatusForbidden {
		t.Errorf("publish as member: %d", r.code)
	}
	if r := f.do(http.MethodPost, "/listings/"+id+"/publish", "seller-admin"); r.code != http.StatusOK {
		t.Fatalf("publish as admin: %d %s", r.code, r.body)
	}

	// Published listings are public.
	if r := f.do(http.MethodGet, "/listings/"+id, ""); r.code != http.StatusOK {
		t.Errorf("anonymous get of published listing: %d", r.code)
	}
	if n := listed("", ""); n != 1 {
		t.Errorf("anonymous sees %d published listings, want 1", n)
	}

	for who, want := range map[string]int{"seller-member": 403, "buyer-admin": 403} {
		if r := f.do(http.MethodPost, "/listings/"+id+"/archive", who); r.code != want {
			t.Errorf("archive as %q: %d, want %d", who, r.code, want)
		}
		if r := f.do(http.MethodDelete, "/listings/"+id, who); r.code != want {
			t.Errorf("delete as %q: %d, want %d", who, r.code, want)
		}
	}
	if r := f.do(http.MethodPost, "/listings/"+id+"/archive", "seller-owner"); r.code != http.StatusOK {
		t.Errorf("archive as owner: %d %s", r.code, r.body)
	}
}

func TestLicenseAccess(t *testing.T) {
	ctx := context.Background()
	f := newAccessFixture(t)
	listingID := f.createListing("seller-owner")
	seats := 5
	license := &License{ID: uuid.New(), ListingID: uuid.MustParse(listingID), OrganizationID: f.buyer,
		LicenseType: LicenseSeatBased, Seats: &seats, ValidFrom: time.Now(), PurchasedBy: f.who["buyer-admin"]}
	if err := NewEntLicenseService(f.db, nil).Grant(ctx, license); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	lid := license.ID.String()

	for who, want := range map[string]int{"buyer-member": 200, "buyer-admin": 200, "outsider": 403, "seller-owner": 403, "": 401} {
		if r := f.do(http.MethodGet, "/licenses?organization_id="+f.buyer.String(), who); r.code != want {
			t.Errorf("list licenses as %q: %d, want %d", who, r.code, want)
		}
	}
	for who, want := range map[string]int{"buyer-member": 200, "outsider": 404, "seller-owner": 404} {
		if r := f.do(http.MethodGet, "/licenses/"+lid, who); r.code != want {
			t.Errorf("get license as %q: %d, want %d", who, r.code, want)
		}
		if r := f.do(http.MethodGet, "/licenses/"+lid+"/seats", who); r.code != want {
			t.Errorf("list seats as %q: %d, want %d", who, r.code, want)
		}
	}

	seat := func(who string) map[string]any { return map[string]any{"principal_id": f.who[who].String()} }
	if r := f.do(http.MethodPost, "/licenses/"+lid+"/seats", "buyer-member", seat("buyer-member")); r.code != http.StatusForbidden {
		t.Errorf("assign as member: %d", r.code)
	}
	if r := f.do(http.MethodPost, "/licenses/"+lid+"/seats", "buyer-admin", seat("outsider")); r.code != http.StatusBadRequest {
		t.Errorf("assign to non-member: %d", r.code)
	}
	spoof := seat("buyer-member")
	spoof["assigned_by"] = f.who["buyer-member"].String()
	if r := f.do(http.MethodPost, "/licenses/"+lid+"/seats", "buyer-admin", spoof); r.code != http.StatusForbidden {
		t.Errorf("assign with someone else as assigner: %d", r.code)
	}
	r := f.do(http.MethodPost, "/licenses/"+lid+"/seats", "buyer-admin", seat("buyer-member"))
	if r.code != http.StatusOK && r.code != http.StatusCreated {
		t.Fatalf("assign as admin: %d %s", r.code, r.body)
	}
	var assigned SeatAssignmentResponse
	if err := json.Unmarshal(r.body, &assigned); err != nil || assigned.AssignedBy != f.who["buyer-admin"].String() {
		t.Errorf("assignment = %+v, %v; want assigned by the caller", assigned, err)
	}
	seatPath := "/licenses/" + lid + "/seats/" + f.who["buyer-member"].String()
	if r := f.do(http.MethodDelete, seatPath, "outsider"); r.code != http.StatusForbidden {
		t.Errorf("unassign as outsider: %d", r.code)
	}
	if r := f.do(http.MethodDelete, seatPath, "buyer-admin"); r.code >= 300 {
		t.Errorf("unassign as admin: %d %s", r.code, r.body)
	}
}

func TestCheckoutDefaultsToOrgManage(t *testing.T) {
	f := newAccessFixture(t)
	payload := map[string]any{"listing_id": uuid.NewString(), "organization_id": f.buyer.String(),
		"success_url": "https://app.example.com/ok", "cancel_url": "https://app.example.com/cancel"}
	for who, want := range map[string]int{"buyer-member": 403, "seller-owner": 403, "buyer-admin": 200} {
		if r := f.do(http.MethodPost, "/checkout", who, payload); r.code != want {
			t.Errorf("checkout as %q: %d, want %d", who, r.code, want)
		}
	}
	if f.checkout.got == nil || f.checkout.got.PurchaserID != f.who["buyer-admin"] {
		t.Errorf("checkout request = %+v", f.checkout.got)
	}
}

// TestOrgScopedOperationsFailClosed verifies that without an authorizer
// only published listings can be read.
func TestOrgScopedOperationsFailClosed(t *testing.T) {
	_, api := humatest.New(t)
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	NewAPI(api, APIConfig{}, entService{listings: NewEntListingService(db, nil), licenses: NewEntLicenseService(db, nil), checkout: &fakeCheckout{}})
	if resp := api.Post("/listings", map[string]any{"creator_org_id": uuid.NewString(), "product_type": "x", "title": "t", "pricing_model": "free", "price_cents": 0, "currency": "USD"}); resp.Code != http.StatusNotImplemented {
		t.Errorf("create listing: %d", resp.Code)
	}
	if resp := api.Get("/licenses?organization_id=" + uuid.NewString()); resp.Code != http.StatusNotImplemented {
		t.Errorf("list licenses: %d", resp.Code)
	}
	if resp := api.Get("/listings"); resp.Code != http.StatusOK {
		t.Errorf("list published listings: %d", resp.Code)
	}
}
