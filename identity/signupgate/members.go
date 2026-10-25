package signupgate

import "time"

// DefaultMemberCodeTTL is how long a member's invite code works when
// MemberOptions.CodeTTL is not set.
const DefaultMemberCodeTTL = 14 * 24 * time.Hour

// MemberOptions configure member invites.
type MemberOptions struct {
	// DefaultAllowance is how many invite codes a member may hold when an
	// operator has not set their allowance. The default is 0: members invite
	// nobody until an operator allows it.
	DefaultAllowance int
	// CodeTTL is how long a member's invite code works. Zero means
	// DefaultMemberCodeTTL.
	CodeTTL time.Duration
}

func (o MemberOptions) withDefaults() MemberOptions {
	if o.DefaultAllowance < 0 {
		o.DefaultAllowance = 0
	}
	if o.CodeTTL <= 0 {
		o.CodeTTL = DefaultMemberCodeTTL
	}
	return o
}
