package middleware

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter 基于令牌桶算法的速率限制器。
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int           // 每分钟允许的请求数
	burst   int           // 突发容量
	cleanup time.Duration // 清理间隔
}

type bucket struct {
	tokens   float64
	lastTime time.Time
	rate     float64 // 每秒补充的 token 数
	burst    float64
}

// NewRateLimiter 创建速率限制器。
// rate: 每分钟允许的请求数（默认 100）。
func NewRateLimiter(ratePerMinute int) *RateLimiter {
	if ratePerMinute <= 0 {
		ratePerMinute = 100
	}
	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    ratePerMinute,
		burst:   ratePerMinute, // 突发容量等于每分钟限制
		cleanup: 5 * time.Minute,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow 检查指定 IP 是否允许请求。
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{
			tokens:   float64(rl.burst),
			lastTime: time.Now(),
			rate:     float64(rl.rate) / 60.0, // 转换为每秒
			burst:    float64(rl.burst),
		}
		rl.buckets[ip] = b
	}

	// 补充 token
	now := time.Now()
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.lastTime = now

	// 消耗 token
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RetryAfter 返回需要等待的秒数。
func (rl *RateLimiter) RetryAfter(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	if !ok {
		return 0
	}
	if b.tokens >= 1 {
		return 0
	}
	// 计算需要等待多久才能获得 1 个 token
	needed := 1.0 - b.tokens
	seconds := needed / b.rate
	return int(seconds) + 1
}

// Middleware 返回速率限制中间件。
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)

		if !rl.Allow(ip) {
			retryAfter := rl.RetryAfter(ip)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"code":429,"message":"请求过于频繁，请 %d 秒后重试"}`, retryAfter)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractIP 从请求中提取客户端 IP。
func extractIP(r *http.Request) string {
	// 优先使用 X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// 取第一个 IP
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	// 使用 X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// 使用 RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// cleanupLoop 定期清理过期的桶。
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, b := range rl.buckets {
			// 超过 10 分钟未活动的桶删除
			if now.Sub(b.lastTime) > 10*time.Minute {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}
