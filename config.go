package gosecure

import (
	"net/http"
	"time"
)

// Config holds the core security configuration for the middleware stack.
type Config struct {
	JWTSecret   []byte
	CSRFAuthKey []byte
	IsDev       bool
}

// Options configures which security features to apply to a handler.
type Options struct {
	MustAuth      bool
	RequiredRole  string
	RateLimit     bool
	RPS           float64
	Burst         int
	LimitEndpoint string
}

// CookieConfig provides configuration for setting HTTP cookies.
type CookieConfig struct {
	Name     string
	Value    string
	Expire   time.Time
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
	Path     string
}

// DefaultOptions returns a sensible default Options configuration.
func DefaultOptions() Options {
	return Options{
		MustAuth:      false,
		RequiredRole:  "",
		RateLimit:     true,
		RPS:           10.0,
		Burst:         20,
		LimitEndpoint: "default",
	}
}

// NewConfig creates a new Config with the provided secrets.
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
