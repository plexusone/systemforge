package signupgate

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/principal"
)

func TestMemberAllowance(t *testing.T) {
	client := newClient(t)
	s := NewCodeStore(client, MemberOptions{})
	ctx := t.Context()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.now = func() time.Time { return now }
	p, err := principal.NewService(client).CreateHuman(ctx, principal.CreateHumanInput{Email: "ada@example.com", DisplayName: "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	member := p.ID

	if _, _, err := s.CreateMemberCode(ctx, member); !errors.Is(err, ErrAllowanceExhausted) {
		t.Fatalf("default allowance of 0: %v", err)
	}
	three := 3
	if err := s.SetAllowance(ctx, member, &three, "early member", nil); err != nil {
		t.Fatal(err)
	}
	var codes []Code
	var values []string
	for range 3 {
		c, v, err := s.CreateMemberCode(ctx, member)
		if err != nil {
			t.Fatal(err)
		}
		if c.Kind != CodeMember || c.MaxUses != 1 || c.ExpiresAt == nil || !c.ExpiresAt.Equal(now.Add(DefaultMemberCodeTTL)) {
			t.Errorf("member code = %+v", c)
		}
		codes, values = append(codes, c), append(values, v)
	}
	if _, _, err := s.CreateMemberCode(ctx, member); !errors.Is(err, ErrAllowanceExhausted) {
		t.Fatalf("fourth code with an allowance of 3: %v", err)
	}

	// A used code keeps counting even when revoked; an unused one revoked
	// gives its slot back.
	id, err := s.Reserve(ctx, values[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Redeem(ctx, id, uuid.New(), "grace@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeMemberCode(ctx, member, codes[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateMemberCode(ctx, member); !errors.Is(err, ErrAllowanceExhausted) {
		t.Fatalf("revoking a used code gave a slot back: %v", err)
	}
	if err := s.RevokeMemberCode(ctx, member, codes[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateMemberCode(ctx, member); err != nil {
		t.Fatalf("revoking an unused code did not give its slot back: %v", err)
	}

	// Expiry gives slots back too.
	now = now.Add(DefaultMemberCodeTTL + time.Hour)
	sum, err := s.MemberInvites(ctx, member)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Allowance != 3 || sum.Held != 1 || sum.Remaining != 2 || len(sum.Codes) != 4 {
		t.Errorf("summary = allowance %d held %d remaining %d codes %d; want 3, 1, 2, 4", sum.Allowance, sum.Held, sum.Remaining, len(sum.Codes))
	}

	other := uuid.New()
	if err := s.RevokeMemberCode(ctx, other, codes[2].ID); !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("another member revoked the code: %v", err)
	}
	if sum, _ := s.MemberInvites(ctx, other); len(sum.Codes) != 0 || sum.Allowance != 0 {
		t.Errorf("another member sees %+v", sum)
	}

	list, err := s.Allowances(ctx)
	if err != nil || len(list) != 1 || list[0].Email != "ada@example.com" || list[0].Effective != 3 || list[0].Held != 1 || list[0].Note != "early member" {
		t.Fatalf("allowances = %+v, %v", list, err)
	}
	if err := s.SetAllowance(ctx, member, nil, "", nil); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.Allowances(ctx); list[0].Granted != nil || list[0].Effective != 0 {
		t.Errorf("reset to default = %+v", list[0])
	}
	if got, err := s.PrincipalByEmail(ctx, "ADA@example.com"); err != nil || got != member {
		t.Errorf("PrincipalByEmail = %s, %v", got, err)
	}
	if _, err := s.PrincipalByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrNoAccount) {
		t.Errorf("unknown address: %v", err)
	}
	neg := -1
	if err := s.SetAllowance(ctx, member, &neg, "", nil); err == nil {
		t.Error("negative allowance accepted")
	}
}

func TestDefaultAllowanceApplies(t *testing.T) {
	s := NewCodeStore(newClient(t), MemberOptions{DefaultAllowance: 1, CodeTTL: time.Hour})
	member := uuid.New()
	c, _, err := s.CreateMemberCode(t.Context(), member)
	if err != nil {
		t.Fatalf("default allowance of 1: %v", err)
	}
	if c.ExpiresAt == nil || c.ExpiresAt.Sub(c.CreatedAt) > time.Hour+time.Minute {
		t.Errorf("expiry %v does not follow the TTL", c.ExpiresAt)
	}
	if _, _, err := s.CreateMemberCode(t.Context(), member); !errors.Is(err, ErrAllowanceExhausted) {
		t.Errorf("second code with a default of 1: %v", err)
	}
}
