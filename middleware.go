package gosecure

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	"github.com/justinas/alice"
	"golang.org/x/time/rate"
)

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

const (
	// UserContextKey is the context key for storing user claims.
	UserContextKey ContextKey = "user"
)

// Apply wraps your HTTP handler with the security middleware stack.
// It applies the following middleware in order:
// 1. Recovery (panic handling)
// 2. Security headers
// 3. CSRF protection
// 4. Rate limiting (if enabled)
// 5. JWT authentication (if enabled)
func Apply(cfg Config, h http.Handler, opts Options) http.Handler {
	csrfMid := csrf.Protect(
		cfg.CSRFAuthKey,
		csrf.Secure(!cfg.IsDev),
		csrf.HttpOnly(true),
		csrf.Path("/"),
		csrf.SameSite(csrf.SameSiteLaxMode),
	)

	chain := alice.New(
		RecoveryMiddleware,
		HeaderMiddleware,
		csrfMid,
	)

	if opts.RateLimit {
		chain = chain.Append(RateLimitMiddleware(opts.RPS, opts.Burst))
	}

	if opts.MustAuth {
		chain = chain.Append(AuthJWTMiddleware(cfg))
	}

	return chain.Then(h)
}

// AuthJWTMiddleware validates JWT tokens from the "auth_token" cookie.
// If authentication fails, it returns a 401 Unauthorized response.
// On success, it adds the JWT claims to the request context under UserContextKey.
func AuthJWTMiddleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("auth_token")
			if err != nil {
				http.Error(w, "Unauthorized: missing auth token", http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
				// Validate the signing method
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return cfg.JWTSecret, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, token.Claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RateLimitMiddleware implements IP-based rate limiting using the token bucket algorithm.
// Each IP address gets its own rate limiter with the specified RPS and burst values.
func RateLimitMiddleware(rps float64, burst int) func(http.Handler) http.Handler {
	var (
		mu       sync.RWMutex
		visitors = make(map[string]*rate.Limiter)
	)

	// Cleanup function to prevent memory leaks
	// In production, you might want to run this periodically
	cleanup := func() {
		mu.Lock()
		defer mu.Unlock()
		visitors = make(map[string]*rate.Limiter)
	}
	_ = cleanup // Available for use if needed

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)

			mu.RLock()
			limiter, exists := visitors[ip]
			mu.RUnlock()

			if !exists {
				mu.Lock()
				limiter = rate.NewLimiter(rate.Limit(rps), burst)
				visitors[ip] = limiter
				mu.Unlock()
			}

			if !limiter.Allow() {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HeaderMiddleware adds security headers to all responses.
// It sets X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy.
func HeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// RecoveryMiddleware recovers from panics and returns a 500 Internal Server Error.
// This prevents the entire server from crashing due to a panic in a handler.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log the error in production
				// log.Printf("panic recovered: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// getIP extracts the client IP address from the request.
// It checks X-Forwarded-For and X-Real-IP headers before falling back to RemoteAddr.
func getIP(r *http.Request) string {
	// Check X-Forwarded-For header (most common with proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// GetUserClaims extracts JWT claims from the request context.
// Returns nil if no claims are found (e.g., on unauthenticated routes).
func GetUserClaims(r *http.Request) jwt.Claims {
	claims, ok := r.Context().Value(UserContextKey).(jwt.Claims)
	if !ok {
		return nil
	}
	return claims
}