package main

import (
	"html"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
)

// assetHandler 返回 Wails AssetServer 使用的处理器。
func (d *Desktop) assetHandler() http.Handler {
	return d.proxy
}

// proxyHandler 把 Wails AssetServer 的请求反向代理到内嵌后端
// （REST API + 由后端 ui 包提供的 React 前端静态资源）。
//
// 后端尚未就绪（启动中或启动失败）时返回内置等待页，页面会自动刷新重试，
// 因此窗口可以在后端初始化完成之前就显示出来，避免白屏。
type proxyHandler struct {
	target atomic.Pointer[url.URL]

	mu    sync.RWMutex
	proxy *httputil.ReverseProxy
}

func newProxyHandler() *proxyHandler {
	return &proxyHandler{}
}

// setTarget 设置代理目标；后端启动完成后调用，此后请求直接转发到内嵌服务。
func (p *proxyHandler) setTarget(target *url.URL) {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		serveWaitingPage(w, err)
	}

	p.target.Store(target)
	p.mu.Lock()
	p.proxy = proxy
	p.mu.Unlock()
}

// clearTarget 清除代理目标；后端重启期间调用，请求将落到等待页。
func (p *proxyHandler) clearTarget() {
	p.mu.Lock()
	p.proxy = nil
	p.mu.Unlock()
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	proxy := p.proxy
	p.mu.RUnlock()

	if proxy == nil {
		serveWaitingPage(w, nil)
		return
	}
	proxy.ServeHTTP(w, r)
}

// serveWaitingPage 输出「本地服务启动中」的等待页。
// cause 非空表示后端连接失败（例如启动失败或已退出）。
func serveWaitingPage(w http.ResponseWriter, cause error) {
	detail := "正在启动本地服务，请稍候..."
	if cause != nil {
		detail = "连接本地服务失败：" + cause.Error()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	// 使用字符串替换而不是 fmt，避免模板中的 CSS 百分号被当成格式动词
	_, _ = io.WriteString(w, strings.Replace(waitingPageHTML, waitingPagePlaceholder, html.EscapeString(detail), 1))
}

// waitingPagePlaceholder 是等待页中注入状态文案的占位符。
const waitingPagePlaceholder = "{{DETAIL}}"

// waitingPageHTML 为等待页模板。
// 页面每 1.5 秒自动刷新，后端就绪后会直接进入正常界面。
const waitingPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>OpenCert Manager</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', sans-serif;
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    color: #c9d1d9;
    display: flex; align-items: center; justify-content: center;
    height: 100vh; overflow: hidden;
  }
  .container { text-align: center; animation: fadeIn .5s ease-out; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
  .logo {
    width: 72px; height: 72px; border-radius: 18px;
    background: linear-gradient(135deg, #1677ff, #722ed1);
    display: inline-flex; align-items: center; justify-content: center;
    box-shadow: 0 8px 32px rgba(22, 119, 255, .4); margin-bottom: 24px;
  }
  .logo svg { width: 36px; height: 36px; fill: #fff; }
  h1 { font-size: 22px; font-weight: 600; margin-bottom: 8px; }
  .subtitle { font-size: 14px; color: #8b949e; margin-bottom: 32px; }
  .spinner {
    width: 40px; height: 40px; border: 3px solid rgba(22, 119, 255, .2);
    border-top-color: #1677ff; border-radius: 50%;
    animation: spin 1s linear infinite; margin: 0 auto 16px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .status { font-size: 13px; color: #6e7681; max-width: 560px; margin: 0 auto; word-break: break-all; }
</style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
    </div>
    <h1>OpenCert Manager</h1>
    <p class="subtitle">正在连接本地服务...</p>
    <div class="spinner"></div>
    <p class="status">{{DETAIL}}</p>
  </div>
  <script>setTimeout(function () { location.reload(); }, 1500);</script>
</body>
</html>`
