// Package middleware 提供轻量级应用指标收集（无需 Prometheus 依赖）。
package middleware

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics 收集应用运行时指标。
type Metrics struct {
	startTime time.Time

	// 请求计数器
	totalRequests  atomic.Int64
	totalErrors4xx atomic.Int64
	totalErrors5xx atomic.Int64

	// 活跃连接/会话
	activeRequests atomic.Int64

	// 延迟直方图（简化版：按桶统计）
	latencyBuckets [6]atomic.Int64 // <10ms, <50ms, <100ms, <500ms, <1s, >=1s

	// 按路径统计（前 50 个路径）
	pathStats   map[string]*pathStat
	pathStatsMu sync.RWMutex
}

type pathStat struct {
	Count    atomic.Int64
	ErrorCnt atomic.Int64
	TotalMs  atomic.Int64
}

// NewMetrics 创建指标收集器。
func NewMetrics() *Metrics {
	return &Metrics{
		startTime: time.Now(),
		pathStats: make(map[string]*pathStat),
	}
}

// RecordRequest 记录一次请求。
func (m *Metrics) RecordRequest(path string, status int, duration time.Duration) {
	m.totalRequests.Add(1)

	if status >= 400 && status < 500 {
		m.totalErrors4xx.Add(1)
	} else if status >= 500 {
		m.totalErrors5xx.Add(1)
	}

	// 延迟桶
	ms := duration.Milliseconds()
	switch {
	case ms < 10:
		m.latencyBuckets[0].Add(1)
	case ms < 50:
		m.latencyBuckets[1].Add(1)
	case ms < 100:
		m.latencyBuckets[2].Add(1)
	case ms < 500:
		m.latencyBuckets[3].Add(1)
	case ms < 1000:
		m.latencyBuckets[4].Add(1)
	default:
		m.latencyBuckets[5].Add(1)
	}

	// 按路径统计（限制最多 100 个路径，防止内存膨胀）
	m.pathStatsMu.RLock()
	ps, ok := m.pathStats[path]
	m.pathStatsMu.RUnlock()

	if !ok {
		m.pathStatsMu.Lock()
		if len(m.pathStats) < 100 {
			ps = &pathStat{}
			m.pathStats[path] = ps
		}
		m.pathStatsMu.Unlock()
	}

	if ps != nil {
		ps.Count.Add(1)
		ps.TotalMs.Add(ms)
		if status >= 400 {
			ps.ErrorCnt.Add(1)
		}
	}
}

// IncrActiveRequests 增加活跃请求数。
func (m *Metrics) IncrActiveRequests() { m.activeRequests.Add(1) }

// DecrActiveRequests 减少活跃请求数。
func (m *Metrics) DecrActiveRequests() { m.activeRequests.Add(-1) }

// metricsResponse 是 /metrics 端点的 JSON 响应结构。
type metricsResponse struct {
	Uptime         string           `json:"uptime"`
	UptimeSeconds  int64            `json:"uptime_seconds"`
	TotalRequests  int64            `json:"total_requests"`
	ActiveRequests int64            `json:"active_requests"`
	Errors4xx      int64            `json:"errors_4xx"`
	Errors5xx      int64            `json:"errors_5xx"`
	Latency        map[string]int64 `json:"latency_buckets"`
	TopPaths       []pathMetric     `json:"top_paths,omitempty"`
}

type pathMetric struct {
	Path   string  `json:"path"`
	Count  int64   `json:"count"`
	Errors int64   `json:"errors"`
	AvgMs  float64 `json:"avg_ms"`
}

// Handler 返回 /metrics 端点的 HTTP 处理函数。
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uptime := time.Since(m.startTime)

		resp := metricsResponse{
			Uptime:         uptime.Round(time.Second).String(),
			UptimeSeconds:  int64(uptime.Seconds()),
			TotalRequests:  m.totalRequests.Load(),
			ActiveRequests: m.activeRequests.Load(),
			Errors4xx:      m.totalErrors4xx.Load(),
			Errors5xx:      m.totalErrors5xx.Load(),
			Latency: map[string]int64{
				"lt_10ms":  m.latencyBuckets[0].Load(),
				"lt_50ms":  m.latencyBuckets[1].Load(),
				"lt_100ms": m.latencyBuckets[2].Load(),
				"lt_500ms": m.latencyBuckets[3].Load(),
				"lt_1s":    m.latencyBuckets[4].Load(),
				"gte_1s":   m.latencyBuckets[5].Load(),
			},
		}

		// 收集路径统计
		m.pathStatsMu.RLock()
		for path, ps := range m.pathStats {
			count := ps.Count.Load()
			if count == 0 {
				continue
			}
			resp.TopPaths = append(resp.TopPaths, pathMetric{
				Path:   path,
				Count:  count,
				Errors: ps.ErrorCnt.Load(),
				AvgMs:  float64(ps.TotalMs.Load()) / float64(count),
			})
		}
		m.pathStatsMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// MetricsMiddleware 返回自动收集请求指标的中间件。
func MetricsMiddleware(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 跳过 /metrics 自身，避免递归统计
			if r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			m.IncrActiveRequests()
			start := time.Now()

			lw := &metricsResponseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(lw, r)

			m.DecrActiveRequests()
			m.RecordRequest(r.URL.Path, lw.status, time.Since(start))
		})
	}
}

// metricsResponseWriter 捕获状态码。
type metricsResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *metricsResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
