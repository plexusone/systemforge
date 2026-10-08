package stripe

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/marketplace"
)

type purchaserFunc func(context.Context, uuid.UUID) (bool, error)

func (f purchaserFunc) IsManaged(ctx context.Context, id uuid.UUID) (bool, error) { return f(ctx, id) }

// TestCheckoutRefusesManagedPurchasers verifies that a managed principal
// is refused before any listing lookup or Stripe call.
func TestCheckoutRefusesManagedPurchasers(t *testing.T) {
	learner := uuid.New()
	svc := NewCheckoutService(Config{}, nil, nil, nil, WithPurchaserChecker(purchaserFunc(
		func(_ context.Context, id uuid.UUID) (bool, error) { return id == learner, nil },
	)))
	if _, err := svc.CreateCheckoutSession(context.Background(), marketplace.CheckoutRequest{PurchaserID: learner}); !errors.Is(err, marketplace.ErrManagedPurchaser) {
		t.Errorf("managed purchaser = %v, want ErrManagedPurchaser", err)
	}

	boom := errors.New("directory down")
	failing := NewCheckoutService(Config{}, nil, nil, nil, WithPurchaserChecker(purchaserFunc(
		func(context.Context, uuid.UUID) (bool, error) { return false, boom },
	)))
	if _, err := failing.CreateCheckoutSession(context.Background(), marketplace.CheckoutRequest{PurchaserID: uuid.New()}); !errors.Is(err, boom) {
		t.Errorf("checker failure = %v, want it returned", err)
	}
}
