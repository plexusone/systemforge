package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Response headers. RateLimit-Policy and RateLimit follow the IETF HTTPAPI
// draft "RateLimit header fields for HTTP"; the X-RateLimit-* headers are
// kept for clients written against them.
const (
	HeaderRateLimitPolicy = "RateLimit-Policy"
	HeaderRateLimit       = "RateLimit"
	HeaderRetryAfter      = "Retry-After"

	HeaderXRateLimitLimit     = "X-RateLimit-Limit"
	HeaderXRateLimitRemaining = "X-RateLimit-Remaining"
	HeaderXRateLimitReset     = "X-RateLimit-Reset"
)

// DefaultPolicyName names a Limiter's policy in RateLimit-Policy when
// WithName is not given.
const DefaultPolicyName = "default"

// RetryAfterSeconds is the Retry-After value for a refused request: the
// wait rounded up to whole seconds, and at least one, so a client never
// retries at once.
func RetryAfterSeconds(d time.Duration) int {
	return max(ceilSeconds(d), 1)
}

// ceilSeconds rounds d up to whole seconds; negative durations are 0.
func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}

// policyName makes name a valid structured-field string: printable ASCII
// without quotes or backslashes.
func policyName(name string) string {
	if name == "" {
		return DefaultPolicyName
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
}

// WriteHeaders adds the rate limit headers for one checked limit: an item
// in RateLimit-Policy (quota q and window w in seconds) and in RateLimit
// (remaining r and seconds to reset t), and sets X-RateLimit-Limit,
// -Remaining and -Reset. Several limits checked for one request each add
// their item.
func WriteHeaders(h http.Header, name string, limit Limit, res Result) {
	name = policyName(name)
	quota := limit.Burst
	if quota <= 0 {
		quota = limit.Rate
	}
	remaining := max(res.Remaining, 0)
	reset := ceilSeconds(time.Until(res.ResetAt))
	h.Add(HeaderRateLimitPolicy, `"`+name+`";q=`+strconv.Itoa(quota)+";w="+strconv.Itoa(max(ceilSeconds(limit.Period), 1)))
	h.Add(HeaderRateLimit, `"`+name+`";r=`+strconv.Itoa(remaining)+";t="+strconv.Itoa(reset))
	h.Set(HeaderXRateLimitLimit, strconv.Itoa(quota))
	h.Set(HeaderXRateLimitRemaining, strconv.Itoa(remaining))
	h.Set(HeaderXRateLimitReset, strconv.FormatInt(res.ResetAt.Unix(), 10))
}

// WriteTooManyRequests answers 429 with Retry-After set to wait (rounded
// up, at least one second).
func WriteTooManyRequests(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set(HeaderRetryAfter, strconv.Itoa(RetryAfterSeconds(wait)))
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}

// writeUnavailable answers 503 for a limit that cannot be checked.
func writeUnavailable(w http.ResponseWriter) {
	w.Header().Set(HeaderRetryAfter, "5")
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
}

// tooManyKeysWait is the Retry-After of a refusal because the storage is
// tracking its maximum number of keys: about when old windows expire.
const tooManyKeysWait = time.Minute
