#!/usr/bin/env bash
#
# 构建 Windows 客户端（x64 / arm64）。
#
# 产物（默认输出到 dist/clients/）：
#   OpenCertManager-windows-amd64.exe    桌面客户端（Go + Wails，GUI 子系统）
#   OpenCertManager-windows-arm64.exe
#   client-card-windows-amd64.exe        本地管理端后端（可注册为 Windows 服务）
#   client-card-windows-arm64.exe
#
# 说明：
#   1. Wails 客户端与 client-card 后端均可在 Linux/macOS 上交叉编译
#      （两者在 Windows 下都不需要 cgo），因此 CI 直接用 ubuntu runner 即可。
#   2. 前端（clients/front）会先构建并同步到 clients/ui/dist，再被
#      clients/ui/embed.go 嵌入 client-card 二进制；桌面端则通过反向代理
#      复用同一份前端产物，所以只需要维护一份前端代码。
#
# 用法：
#   ./scripts/build-clients.sh [版本号]
#
# 环境变量：
#   VERSION        版本号（默认：git describe；无 tag 时为 dev）
#   OUT_DIR        输出目录（默认：<repo>/dist/clients）
#   SKIP_FRONTEND  置 1 跳过前端构建（复用 clients/ui/dist 中已有产物）
#   FORCE_NPM_CI   置 1 强制 npm ci（默认仅在 node_modules 缺失时执行）
#   ARCHES         目标架构列表（默认："amd64 arm64"）

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-${VERSION:-$(git -C "${ROOT}" describe --tags --always --dirty 2>/dev/null || echo dev)}}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
OUT_DIR="${OUT_DIR:-${ROOT}/dist/clients}"
ARCHES="${ARCHES:-amd64 arm64}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

command -v go >/dev/null 2>&1 || die "未找到 go，请先安装 Go 1.22+"

info "版本=${VERSION} 提交=${COMMIT} 架构=${ARCHES}"
mkdir -p "${OUT_DIR}"

# ---------------------------------------------------------------- 前端
if [[ "${SKIP_FRONTEND:-0}" == "1" ]]; then
  [[ -f "${ROOT}/clients/ui/dist/index.html" ]] \
    || die "SKIP_FRONTEND=1 但 clients/ui/dist/index.html 不存在，无法嵌入前端"
  warn "跳过前端构建，复用 clients/ui/dist 现有产物"
else
  command -v npm >/dev/null 2>&1 || die "未找到 npm，构建前端需要 Node.js 18+"
  info "构建前端 (clients/front)"
  pushd "${ROOT}/clients/front" >/dev/null
  if [[ "${FORCE_NPM_CI:-0}" == "1" || ! -d node_modules ]]; then
    npm ci --no-audit --no-fund
  fi
  npm run build
  popd >/dev/null

  info "同步前端产物到 clients/ui/dist（供 go:embed 嵌入）"
  rm -rf "${ROOT}/clients/ui/dist"
  mkdir -p "${ROOT}/clients/ui/dist"
  cp -R "${ROOT}/clients/front/dist/." "${ROOT}/clients/ui/dist/"
fi

# ---------------------------------------------------------------- 二进制
CARD_LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.Commit=${COMMIT}"
# 桌面端额外使用 -H windowsgui：生产构建不弹控制台窗口
APP_LDFLAGS="-s -w -H windowsgui -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.Commit=${COMMIT}"

for arch in ${ARCHES}; do
  info "构建 client-card (windows/${arch})"
  (
    cd "${ROOT}/clients"
    CGO_ENABLED=0 GOOS=windows GOARCH="${arch}" \
      go build -trimpath -ldflags "${CARD_LDFLAGS}" \
      -o "${OUT_DIR}/client-card-windows-${arch}.exe" ./cmd/client-card
  )

  info "构建 OpenCert Manager (windows/${arch})"
  (
    cd "${ROOT}/desktop/wails"
    CGO_ENABLED=0 GOOS=windows GOARCH="${arch}" \
      go build -trimpath -tags "desktop,production" -ldflags "${APP_LDFLAGS}" \
      -o "${OUT_DIR}/OpenCertManager-windows-${arch}.exe" .
  )
done

# ---------------------------------------------------------------- 清单
info "构建产物："
if command -v sha256sum >/dev/null 2>&1; then
  ( cd "${OUT_DIR}" && sha256sum ./*.exe | tee SHA256SUMS )
else
  ls -lh "${OUT_DIR}"/*.exe
fi
