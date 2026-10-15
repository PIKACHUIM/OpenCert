#!/usr/bin/env bash
#
# 构建云端平台（server-card）服务端二进制。
#
# 产物（默认输出到 dist/server/）：
#   server-card-linux-amd64
#   server-card-linux-arm64
#   web/                           （门户 + 控制台前端产物，需与二进制同级目录）
#     index.html
#     assets/...
#   SHA256SUMS
#
# 前端产物来自 servers/front 的生产构建（npm run build）。
# 服务端通过 SERVER_CARD_WEB_ROOT 指定资源目录，默认读取二进制同级的 web/。
#
# 二进制以 CGO_ENABLED=0 静态编译，可直接用于 alpine/scratch 镜像
# （scripts/docker/Dockerfile 只做封装，不在容器内编译）。
#
# 用法：
#   ./scripts/build-server.sh [版本号]
#
# 环境变量：
#   VERSION       版本号（默认：git describe；无 tag 时为 dev）
#   OUT_DIR       输出目录（默认：<repo>/dist/server）
#   TARGETS       目标平台列表，格式 "<os>/<arch>"（默认："linux/amd64 linux/arm64"）
#   SKIP_FRONTEND 置 1 时跳过前端构建，直接使用既有的 servers/front/dist

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-${VERSION:-$(git -C "${ROOT}" describe --tags --always --dirty 2>/dev/null || echo dev)}}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
OUT_DIR="${OUT_DIR:-${ROOT}/dist/server}"
TARGETS="${TARGETS:-linux/amd64 linux/arm64}"
SKIP_FRONTEND="${SKIP_FRONTEND:-0}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

command -v go >/dev/null 2>&1 || die "未找到 go，请先安装 Go 1.22+"

LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.Commit=${COMMIT}"

info "版本=${VERSION} 提交=${COMMIT} 目标=${TARGETS}"
mkdir -p "${OUT_DIR}"

for target in ${TARGETS}; do
  os="${target%%/*}"
  arch="${target##*/}"
  suffix=""
  [[ "${os}" == "windows" ]] && suffix=".exe"

  info "构建 server-card (${os}/${arch})"
  (
    cd "${ROOT}/servers"
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" \
      go build -trimpath -ldflags "${LDFLAGS}" \
      -o "${OUT_DIR}/server-card-${os}-${arch}${suffix}" ./cmd/server-card
  )
done

# 运行时静态资源：门户与控制台由前端构建产物提供，需与二进制同级
if [[ "${SKIP_FRONTEND}" == "1" ]]; then
  [[ -f "${ROOT}/servers/front/dist/index.html" ]] \
    || die "SKIP_FRONTEND=1 但 servers/front/dist/index.html 不存在，无法部署前端"
  info "跳过前端构建，使用既有 servers/front/dist"
else
  command -v npm >/dev/null 2>&1 || die "未找到 npm，请先安装 Node.js 18+"
  info "构建前端 servers/front（门户 + 控制台）"
  (
    cd "${ROOT}/servers/front"
    # 优先使用 lockfile 保证可复现安装；无 lockfile 时退回 install
    if [[ -f package-lock.json ]]; then
      npm ci --no-audit --no-fund
    else
      npm install --no-audit --no-fund
    fi
    npm run build
  )
fi

info "复制静态资源 servers/front/dist -> ${OUT_DIR}/web"
rm -rf "${OUT_DIR}/web"
mkdir -p "${OUT_DIR}/web"
cp -R "${ROOT}/servers/front/dist/." "${OUT_DIR}/web/"

info "构建产物："
if command -v sha256sum >/dev/null 2>&1; then
  ( cd "${OUT_DIR}" && sha256sum ./server-card-* | tee SHA256SUMS )
else
  ls -lh "${OUT_DIR}"/server-card-*
fi
