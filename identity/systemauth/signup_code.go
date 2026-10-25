package systemauth

import "context"

// SignupGateAborter is implemented by a SignupGate that reserves something
// in AllowSignup, such as one use of an invite code. SignupAborted is called
// when account creation fails after AllowSignup allowed it, so the gate can
// give the reservation back. It is not called when AllowSignup refused.
type SignupGateAborter interface {
	SignupAborted(ctx context.Context, login ExternalLogin)
}

// signupCodeKey carries the invite code a person brought to sign-in.
type signupCodeKey struct{}

// WithSignupCode returns ctx carrying the invite code a person brought to
// sign-in, for the sign-up gate to read. SystemAuth sets it from the sign-up
// code cookie before resolving a social login.
func WithSignupCode(ctx context.Context, code string) context.Context {
	if code == "" {
		return ctx
	}
	return context.WithValue(ctx, signupCodeKey{}, code)
}

// SignupCodeFromContext returns the invite code carried by ctx, or "".
func SignupCodeFromContext(ctx context.Context) string {
	code, _ := ctx.Value(signupCodeKey{}).(string) //nolint:errcheck // a type assertion, not an error: absent means no code
	return code
}
