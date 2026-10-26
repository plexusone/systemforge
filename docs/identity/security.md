# Account Security

SystemForge provides security features for identity management including account lockout protection against brute-force attacks.

## Account Lockout

The lockout package protects against brute-force password attacks by temporarily locking accounts after repeated failed login attempts.

### Features

- Configurable max attempts and lockout duration
- Sliding window for attempt tracking
- Memory and Redis storage backends
- Manual lock/unlock capabilities
- Automatic expired lock cleanup

### Quick Start

```go
import (
    "github.com/plexusone/systemforge/identity/security"
)

// Create a memory store for development
store := security.NewMemoryLockoutStore()

// Create the lockout service
lockout := security.NewLockout(store,
    security.WithMaxAttempts(5),
    security.WithLockoutDuration(15*time.Minute),
)
defer lockout.Close()

// In your login handler
func handleLogin(ctx context.Context, email, password string) error {
    // Check and record in one call (recommended)
    success := validateCredentials(email, password)
    err := lockout.CheckAndRecord(ctx, email, success)
    if err != nil {
        if errors.Is(err, security.ErrAccountLocked) {
            return fmt.Errorf("account locked, try again later")
        }
        return err
    }

    if !success {
        return fmt.Errorf("invalid credentials")
    }

    // Login successful
    return nil
}
```

### Configuration

#### Lockout Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithMaxAttempts(n)` | Failed attempts before lockout | 5 |
| `WithLockoutDuration(d)` | How long account stays locked | 15 minutes |
| `WithLockoutConfig(cfg)` | Full configuration struct | See below |

#### Config Struct

```go
cfg := security.LockoutConfig{
    MaxAttempts:     5,                // Lock after 5 failures
    LockoutDuration: 15 * time.Minute, // Lock for 15 minutes
    AttemptWindow:   15 * time.Minute, // Only count recent attempts
    CleanupInterval: 5 * time.Minute,  // Clean up old data every 5 min
}

lockout := security.NewLockout(store, security.WithLockoutConfig(cfg))
```

### Storage Backends

#### Memory Store

For development and single-instance deployments:

```go
store := security.NewMemoryLockoutStore(
    security.WithLockoutCleanupInterval(5*time.Minute),
)
```

#### Redis Store

For production and multi-instance deployments:

```go
import "github.com/redis/go-redis/v9"

client := redis.NewClient(&redis.Options{
    Addr: "localhost:6379",
})

store := security.NewRedisLockoutStore(client,
    security.WithRedisKeyPrefix("myapp:lockout:"),
)
```

### API Reference

#### Checking Lock Status

```go
// Check if an account is currently locked
locked, err := lockout.IsLocked(ctx, identifier)

// Get detailed status
status, err := lockout.GetStatus(ctx, identifier)
fmt.Printf("Locked: %v\n", status.IsLocked)
fmt.Printf("Failed attempts: %d\n", status.FailedAttempts)
fmt.Printf("Remaining attempts: %d\n", status.RemainingAttempts)
fmt.Printf("Locked until: %v\n", status.LockedUntil)
```

#### Recording Attempts

```go
// Record a failed attempt (may trigger lockout)
err := lockout.RecordFailure(ctx, identifier)
if errors.Is(err, security.ErrAccountLocked) {
    // Account is now locked
}

// Record a successful login (resets attempt counter)
err := lockout.RecordSuccess(ctx, identifier)

// Combined check-and-record (recommended for login flows)
err := lockout.CheckAndRecord(ctx, identifier, success)
```

#### Manual Lock Management

```go
// Manually lock an account (e.g., admin action)
err := lockout.Lock(ctx, identifier, time.Now().Add(24*time.Hour))

// Manually unlock an account
err := lockout.Unlock(ctx, identifier)

// Reset all lockout state
err := lockout.Reset(ctx, identifier)
```

### Lockout Status

The `LockoutStatus` struct contains:

```go
type LockoutStatus struct {
    IsLocked          bool      // Account currently locked
    FailedAttempts    int       // Failed attempts in window
    RemainingAttempts int       // Attempts before lockout
    LockedUntil       time.Time // When lock expires
    LastAttempt       time.Time // Last failed attempt time
}
```

### Best Practices

1. **Use email as identifier**: Lock by email/username, not by IP (IPs can be shared)

2. **Show remaining attempts**: Help legitimate users avoid lockout
   ```go
   status, _ := lockout.GetStatus(ctx, email)
   if status.RemainingAttempts <= 2 {
       log.Printf("Warning: %d attempts remaining", status.RemainingAttempts)
   }
   ```

3. **Combine with rate limiting**: Add IP-based rate limiting for defense in depth

4. **Log lockout events**: Monitor for attack patterns
   ```go
   err := lockout.RecordFailure(ctx, email)
   if errors.Is(err, security.ErrAccountLocked) {
       log.Printf("Account locked: %s", email)
       // Alert security team for repeated lockouts
   }
   ```

5. **Provide recovery path**: Allow password reset to unlock accounts

### Errors

| Error | Description |
|-------|-------------|
| `ErrAccountLocked` | Account is currently locked |
| `ErrStorageFailure` | Storage backend error |
| `ErrInvalidThreshold` | Invalid configuration value |

## Login Tokens

A [managed principal](managed-principals.md) signs in with a manager-issued
login token, which is password-equivalent for that principal while it is
valid. The mitigations are structural:

- Tokens are 256-bit random values stored only as SHA-256 hashes and
  compared in constant time; their values appear once, at issue, and never
  in listings, audit events, or logs.
- They expire: 30 days by default, never more than the 400-day ceiling, and
  20 minutes for single-use tokens, which succeed at most once even under
  concurrent presentation.
- The `POST /login-token` exchange gives every failure the same response
  and is rate limited per source address and per client. It accepts only
  forms posted from the issuer's origin or an allowed redirect origin, so
  another site cannot sign a visitor into an account it controls.
- Managed principals carry reduced capabilities: they cannot manage their
  own profile or delegate.
- Managers see every live token and session and can revoke any of them, or
  all at once; every issue and revocation is audited.

Applications that need stronger assurance can issue single-use tokens or add
device binding of their own.
