#!/usr/bin/env bash
#
# 用预编译二进制封装 server-card 的 Docker 镜像（多架构）。
#
# 前置：先执行 ./scripts/build-server.sh 生成 dist/server/ 下的二进制。
#
# 用法：
#   ./scripts/build-docker.sh [版本号]
#
# 环境变量：
#   IMAGE       镜像名（默认 opencert/server-card）
#   VERSION     版本号（默认：git describe；无 tag 时为 dev）
#   PLATFORMS   推送时的目标平台（默认 linux/amd64,linux/arm64）
#   LOCAL_PLATFORM 本地构建（不推送）时的平台（默认 linux/amd64）
#   PUSH        置 1 构建多架构并推送；否则只构建单架构并 --load 到本地
#   ALSO_LATEST 置 1 时额外打上 :latest 标签
#
# 示例：
#   ./scripts/build-docker.sh v2.1.0                                  # 本地单架构
#   PUSH=1 ALSO_LATEST=1 IMAGE=ghcr.io/me/opencert/server-card ./scripts/build-docker.sh v2.1.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-${VERSION:-$(git -C "${ROOT}" describe --tags --always --dirty 2>/dev/null || echo dev)}}"
# Docker tag 只允许 [A-Za-z0-9_.-]，例如 "v0.0.0-beta.20260101+ab12cd3" 需要转换为合法 tag
TAG="${VERSION//[^A-Za-z0-9_.-]/-}"
IMAGE="${IMAGE:-opencert/server-card}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
LOCAL_PLATFORM="${LOCAL_PLATFORM:-linux/amd64}"
OUT_DIR="${OUT_DIR:-${ROOT}/dist/server}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "未找到 docker"

# 镜像只封装二进制，因此先校验产物是否齐全
missing=0
for arch in amd64 arm64; do
  [[ -f "${OUT_DIR}/server-card-linux-${arch}" ]] || { echo "缺少 ${OUT_DIR}/server-card-linux-${arch}"; missing=1; }
done
[[ -d "${OUT_DIR}/web" ]] || { echo "缺少 ${OUT_DIR}/web（运行时静态资源）"; missing=1; }
[[ "${missing}" == "0" ]] || die "请先执行 ./scripts/build-server.sh 生成二进制"

TAGS=(--tag "${IMAGE}:${TAG}")
[[ "${ALSO_LATEST:-0}" == "1" ]] && TAGS+=(--tag "${IMAGE}:latest")

if [[ "${PUSH:-0}" == "1" ]]; then
  info "构建并推送多架构镜像 ${IMAGE}:${TAG} (${PLATFORMS})"
  docker buildx build \
    --platform "${PLATFORMS}" \
    --file "${ROOT}/scripts/docker/Dockerfile" \
    --build-arg "VERSION=${VERSION}" \
    "${TAGS[@]}" \
    --push \
    "${ROOT}"
else
  info "构建本地单架构镜像 ${IMAGE}:${TAG} (${LOCAL_PLATFORM})"
  docker buildx build \
    --platform "${LOCAL_PLATFORM}" \
    --file "${ROOT}/scripts/docker/Dockerfile" \
    --build-arg "VERSION=${VERSION}" \
    "${TAGS[@]}" \
    --load \
    "${ROOT}"
fi

info "完成：${IMAGE}:${TAG}"
