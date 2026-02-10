package gosecure

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
)

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stack := debug.Stack()

				slog.Error("CRITICAL PANIC RECOVERED",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", getIP(r),
					"stack", string(stack),
				)

				w.Header().Set("Connection", "close")
				
				if w.Header().Get("Content-Type") == "" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					
					response := map[string]string{
						"error":   "internal_server_error",
						"message": "An unexpected error occurred. Please try again later.",
					}

					_ = json.NewEncoder(w).Encode(response)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}
