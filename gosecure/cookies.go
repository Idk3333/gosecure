package gosecure

import (
	"net/http"
	"time"
)

// SetCookie sets an HTTP cookie using the provided configuration.
func SetCookie(w http.ResponseWriter, cfg CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    cfg.Value,
		Expires:  cfg.Expire,
		Secure:   cfg.Secure,
		HttpOnly: cfg.HttpOnly,
		SameSite: cfg.SameSite,
		Path:     cfg.Path,
	})
}

// GetCookie retrieves a cookie value by name from the request.
// Returns an error if the cookie is not found.
func GetCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// ClearCookie removes a cookie by setting its expiration to the past.
func ClearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

// SetAuthCookie is a convenience function for setting authentication cookies.
// It sets secure defaults suitable for JWT tokens.
func SetAuthCookie(w http.ResponseWriter, token string, expire time.Time, secure bool) {
	cfg := CookieConfig{
		Name:     "auth_token",
		Value:    token,
		Expire:   expire,
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
	SetCookie(w, cfg)
}

// ClearAuthCookie removes the authentication cookie.
func ClearAuthCookie(w http.ResponseWriter) {
	ClearCookie(w, "auth_token")
}