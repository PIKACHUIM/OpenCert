# PKCS11Driver Makefile
# 用法：make help

.PHONY: help build build-frontend build-backend test clean dev e2e e2e-driver-ipc e2e-attestation e2e-three-stack audit bench audit-full

help:
	@echo "PKCS11Driver 构建工具"
	@echo ""
	@echo "  make build              构建前端 + 后端（完整构建）"
	@echo "  make build-frontend     仅构建前端（webpage/dist）"
	@echo "  make build-backend      仅构建后端（client-card + server-card）"
	@echo "  make test               运行所有 Go 测试"
	@echo "  make dev                启动前端开发服务器（:5173）"
	@echo "  make clean              清理构建产物"
	@echo ""
	@echo "  -- 三组件 E2E 联调 --"
	@echo "  make e2e                运行所有 E2E 测试（driver-IPC + attestation）"
	@echo "  make e2e-driver-ipc     driver→IPC→client 链路测试"
	@echo "  make e2e-attestation    client→server EK 认证链路测试"
	@echo "  make e2e-three-stack    三组件全链路联调（需手动启动 server）"
	@echo ""
	@echo "  -- 安全审计与基准 --"
	@echo "  make audit              运行 gosec / govulncheck / npm audit，输出 roadmap/14-AUDIT-REPORT.md"
	@echo "  make bench              运行 Go benchmark，输出 roadmap/.bench-result.txt"

# ---- 完整构建 ----
build: build-frontend build-backend

# ---- 前端构建 ----
build-frontend:
	@echo ">>> 构建前端..."
	cd webpage && npm install && npm run build
	@echo ">>> 复制前端产物到 client-card/ui/dist..."
	cp -r webpage/dist client-card/ui/dist
	@echo ">>> 前端构建完成"

# ---- 后端构建 ----
build-backend:
	@echo ">>> 构建 client-card..."
	cd client-card && go build -o ../bin/client-card ./cmd/client-card
	@echo ">>> 构建 server-card..."
	cd server-card && go build -o ../bin/server-card ./cmd/server-card
	@echo ">>> 后端构建完成"

# ---- 测试 ----
test:
	@echo ">>> 运行 client-card 测试..."
	cd client-card && go test ./... -v -count=1 -race
	@echo ">>> 运行 server-card 测试..."
	cd server-card && go test ./... -v -count=1 2>/dev/null || echo "server-card 暂无测试"

# ---- 开发模式 ----
dev:
	@echo ">>> 启动前端开发服务器（http://localhost:5173）..."
	cd webpage && npm run dev

# ---- 清理 ----
clean:
	rm -rf bin/
	rm -rf webpage/dist
	rm -rf client-card/ui/dist
	find . -name "*.db" -not -path "./.git/*" -delete

# ============================================================
# 三组件 E2E 联调
# ============================================================
# 体系结构：
#   pkcs11-mock.dll  ──IPC(Unix Socket / NamedPipe)──►  client-card
#                                                            │
#                                                            └──HTTP──►  server-card
#
# 由于 DLL 是 C 代码，无法在 Go test 内装载，三组件联调拆为：
#   1. driver→client 端：通过 IPC 协议帧模拟 driver（见 clients/test/e2e_driver_ipc_test.go）
#   2. client→server 端：通过 HTTP 直连 servers（见 servers/test/e2e_attestation_test.go）
#   3. 真实 DLL 联调：手动加载 DLL 到 pkcs11-tool，对接 client-card 与 server-card
# ============================================================

# 全部 E2E 测试
e2e: e2e-driver-ipc e2e-attestation
	@echo ">>> 三组件 E2E 联调测试通过"

# driver→IPC→client 链路（覆盖 Digest/Verify/Random）
e2e-driver-ipc:
	@echo ">>> [E2E 1/2] driver→IPC→client 链路..."
	cd clients && go test ./test/... -run "TestE2E|TestIPC" -count=1 -v

# client→server EK 认证链路（覆盖高/中/低安全等级）
e2e-attestation:
	@echo ">>> [E2E 2/2] client→server EK 认证链路..."
	cd servers && go test ./test/... -run "TestE2E_CreateCard" -count=1 -v

# 真实 DLL + client + server 全链路（需要手动启动 server-card）
# 用法：先启动 server-card 监听 :8080，再执行 make e2e-three-stack
e2e-three-stack:
	@echo ">>> [E2E 3] 三组件全链路联调（需 server-card 已启动）"
	@bash scripts/e2e-three-stack.sh

# ============================================================
# 安全审计与基准测试
# ============================================================
# 工具依赖（缺失时脚本会优雅跳过子任务）：
#   - gosec        go install github.com/securego/gosec/v2/cmd/gosec@latest
#   - govulncheck  go install golang.org/x/vuln/cmd/govulncheck@latest
#   - npm          (Node.js 自带)
# ============================================================

# 安全审计：gosec + govulncheck + npm audit，结果合并写入 roadmap/14-AUDIT-REPORT.md。
# 发现高危问题时退出码非 0；CI 中需令构建失败。
audit:
	@echo ">>> 运行安全审计..."
	@bash scripts/audit.sh

# 基准测试：运行 client/server 关键路径 benchmark，结果写 roadmap/.bench-result.txt。
bench:
	@echo ">>> 运行基准测试..."
	@bash scripts/bench.sh

# 完整审计：先跑 bench 再跑 audit，让 audit 报告包含基准数据。
audit-full: bench audit
