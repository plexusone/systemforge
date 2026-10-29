package marketplace

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

// TestInternalErrorTextIsNotSent expects a database failure to answer a
// generic 500 that carries none of the driver's error text.
func TestInternalErrorTextIsNotSent(t *testing.T) {
	f := newAccessFixture(t)
	listingID := f.createListing("seller-owner")
	// A closed client fails every query with the driver's text.
	if err := f.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/listings/" + listingID},
		{http.MethodGet, "/listings"},
		{http.MethodGet, "/licenses/" + uuid.NewString()},
	} {
		r := f.do(req.method, req.path, "seller-owner")
		if r.code != http.StatusInternalServerError {
			t.Errorf("%s %s = %d, want 500: %s", req.method, req.path, r.code, r.body)
		}
		body := strings.ToLower(string(r.body))
		for _, leak := range []string{"sql", "closed", "database"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s %s body leaks %q: %s", req.method, req.path, leak, r.body)
			}
		}
	}
}

// TestListingErrorsKeepActionableMessages expects validation failures to
// keep a fixed, actionable message without the validator's text.
func TestListingErrorsKeepActionableMessages(t *testing.T) {
	f := newAccessFixture(t)
	ctx := context.Background()

	// Huma's schema catches most bad input first; an Ent validator
	// failure keeps only the field name.
	verr := NewEntListingService(f.db, nil).Create(ctx, &Listing{
		ID: uuid.New(), CreatorOrgID: f.seller, OwnerID: f.who["seller-owner"],
		ProductType: "course", Title: "Course", PricingModel: "bogus", Currency: "USD",
	})
	if !errors.Is(verr, ErrInvalidListing) {
		t.Fatalf("Create with a bad pricing model = %v, want ErrInvalidListing", verr)
	}
	var se huma.StatusError
	if !errors.As(listingError(ctx, "op", verr), &se) || se.GetStatus() != http.StatusBadRequest ||
		!strings.Contains(se.Error(), "invalid listing") || strings.Contains(se.Error(), "validator") {
		t.Errorf("listingError(validation) = %v, want 400 invalid listing without the validator text", se)
	}

	id := f.createListing("seller-owner")
	if r := f.do(http.MethodPost, "/listings/"+id+"/publish", "seller-owner"); r.code != http.StatusOK {
		t.Fatalf("publish = %d %s", r.code, r.body)
	}
	r := f.do(http.MethodDelete, "/listings/"+id, "seller-owner")
	if r.code != http.StatusBadRequest || !strings.Contains(string(r.body), ErrListingNotDeletable.Error()) {
		t.Errorf("delete published = %d %s, want 400 %q", r.code, r.body, ErrListingNotDeletable)
	}
}
