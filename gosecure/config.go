// Package gosecure provides HTTP security middleware for Go web applications.
// It includes CSRF protection, JWT authentication, rate limiting, and security headers.
package gosecure

import (
	"net/http"
	"time"
)

// Config holds the core security configuration for the middleware stack.
type Config struct {
	// JWTSecret is the secret key used to validate JWT tokens.
	// This should be a secure random value and kept secret.
	JWTSecret []byte

	// CSRFAuthKey is the authentication key for CSRF protection.
	// Must be 32 bytes for gorilla/csrf.
	CSRFAuthKey []byte

	// IsDev indicates if the application is running in development mode.
	// When true, CSRF cookies will not require HTTPS.
	IsDev bool
}

// Options configures which security features to apply to a handler.
type Options struct {
	// MustAuth requires JWT authentication for this handler.
	MustAuth bool

	// RateLimit enables IP-based rate limiting.
	RateLimit bool

	// RPS is the requests-per-second limit per IP address.
	// Only used when RateLimit is true.
	RPS float64

	// Burst is the maximum burst size for rate limiting.
	// Only used when RateLimit is true.
	Burst int
}

// CookieConfig provides configuration for setting HTTP cookies.
type CookieConfig struct {
	// Name is the cookie name.
	Name string

	// Value is the cookie value.
	Value string

	// Expire is the cookie expiration time.
	Expire time.Time

	// Secure indicates if the cookie should only be sent over HTTPS.
	Secure bool

	// HttpOnly prevents JavaScript access to the cookie.
	HttpOnly bool

	// SameSite controls cross-site cookie behavior.
	SameSite http.SameSite

	// Path specifies the cookie path.
	Path string
}

// DefaultOptions returns a sensible default Options configuration.
func DefaultOptions() Options {
	return Options{
		MustAuth:  false,
		RateLimit: true,
		RPS:       10.0,
		Burst:     20,
	}
}

// NewConfig creates a new Config with the provided secrets.
// The CSRF key must be exactly 32 bytes.
func NewConfig(jwtSecret, csrfKey []byte, isDev bool) Config {
	if len(csrfKey) != 32 {
		panic("CSRF key must be exactly 32 bytes")
	}
	return Config{
		JWTSecret:   jwtSecret,
		CSRFAuthKey: csrfKey,
		IsDev:       isDev,
	}
}