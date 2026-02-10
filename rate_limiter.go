package gosecure

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimitConfig struct {
	Name            string
	RPS             float64
	Burst           int
	TimeoutDuration time.Duration
	Message         string
}

type visitorInfo struct {
	limiter      *rate.Limiter
	lastSeen     time.Time
	timeoutUntil time.Time
}

type RateLimitManager struct {
	configs  map[string]RateLimitConfig
	visitors map[string]map[string]*visitorInfo
	mu       sync.RWMutex
}

func NewRateLimitManager() *RateLimitManager {
	rlm := &RateLimitManager{
		configs:  make(map[string]RateLimitConfig),
		visitors: make(map[string]map[string]*visitorInfo),
	}
	go rlm.cleanup()
	return rlm
}

func (rlm *RateLimitManager) AddEndpoint(endpoint string, config RateLimitConfig) {
	rlm.mu.Lock()
	defer rlm.mu.Unlock()
	rlm.configs[endpoint] = config
	rlm.visitors[endpoint] = make(map[string]*visitorInfo)
}

func (rlm *RateLimitManager) Middleware(endpoint string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rlm.mu.RLock()
			config, exists := rlm.configs[endpoint]
			rlm.mu.RUnlock()

			if !exists {
				next.ServeHTTP(w, r)
				return
			}

			ip := getIP(r)

			rlm.mu.Lock()
			endpointVisitors := rlm.visitors[endpoint]
			v, exists := endpointVisitors[ip]
			if !exists {
				v = &visitorInfo{
					limiter:  rate.NewLimiter(rate.Limit(config.RPS), config.Burst),
					lastSeen: time.Now(),
				}
				endpointVisitors[ip] = v
			}
			v.lastSeen = time.Now()

			if time.Now().Before(v.timeoutUntil) {
				rlm.mu.Unlock()
				rlm.handleTimeout(w, r, endpoint, config, v.timeoutUntil)
				return
			}
			rlm.mu.Unlock()

			if !v.limiter.Allow() {
				rlm.mu.Lock()
				v.timeoutUntil = time.Now().Add(config.TimeoutDuration)
				rlm.mu.Unlock()
				rlm.respondRateLimited(w, r, endpoint, config)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (rlm *RateLimitManager) handleTimeout(w http.ResponseWriter, r *http.Request, endpoint string, config RateLimitConfig, until time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "locked", "message": config.Message, "until": until.Format(time.RFC3339),
	})
}

func (rlm *RateLimitManager) respondRateLimited(w http.ResponseWriter, r *http.Request, endpoint string, config RateLimitConfig) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "rate_limit_exceeded", "message": config.Message,
	})
}

func (rlm *RateLimitManager) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		rlm.mu.Lock()
		for _, visitors := range rlm.visitors {
			for ip, v := range visitors {
				if time.Since(v.lastSeen) > 30*time.Minute {
					delete(visitors, ip)
				}
			}
		}
		rlm.mu.Unlock()
	}
}