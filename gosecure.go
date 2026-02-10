package gosecure

import (
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/justinas/alice"
)

type ContextKey string
const UserContextKey ContextKey = "user"

func Apply(cfg Config, rlm *RateLimitManager, h http.Handler, opts Options) http.Handler {
	csrfMid := csrf.Protect(
		cfg.CSRFAuthKey,
		csrf.Secure(!cfg.IsDev),
		csrf.HttpOnly(true),
		csrf.Path("/"),
		csrf.SameSite(csrf.SameSiteLaxMode),
	)

	chain := alice.New(RecoveryMiddleware, HeaderMiddleware, csrfMid)

	if opts.RateLimit && rlm != nil {
		chain = chain.Append(rlm.Middleware(opts.LimitEndpoint))
	}

	if opts.MustAuth {
		chain = chain.Append(AuthJWTMiddleware(cfg, opts.RequiredRole))
	}

	return chain.Then(h)
}

func getIP(r *http.Request) string {
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
