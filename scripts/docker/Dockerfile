# syntax=docker/dockerfile:1
#
# OpenCert 云端平台（server-card）运行镜像。
#
# 该镜像**不负责编译**：二进制由 scripts/build-server.sh 预先构建（CGO_ENABLED=0 静态链接），
# 这里只做封装。构建前请先执行：
#
#   ./scripts/build-server.sh            # 产出 dist/server/server-card-linux-{amd64,arm64}
#   ./scripts/build-docker.sh            # 封装镜像（或直接用下面的 docker buildx 命令）
#
# 手动构建（构建上下文必须是仓库根目录）：
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f scripts/docker/Dockerfile \
#     --build-arg VERSION=2.1.0 \
#     -t opencert/server-card:2.1.0 .

FROM alpine:3.20

# buildx 会自动注入 TARGETARCH（amd64 / arm64），用于挑选对应架构的预编译二进制
ARG TARGETARCH=amd64
ARG VERSION=dev

LABEL org.opencontainers.image.title="OpenCert Server (server-card)" \
      org.opencontainers.image.description="OpenCert 云端 CA / 智能卡 / 证书管理平台" \
      org.opencontainers.image.vendor="GlobalTrusts" \
      org.opencontainers.image.version="${VERSION}"

# ca-certificates：ACME / OCSP / CRL 等出站 TLS 需要
# tzdata：证书有效期等时间显示需要
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -g 10001 -S opencert \
 && adduser -u 10001 -S -G opencert -H -h /app opencert

WORKDIR /app

COPY dist/server/server-card-linux-${TARGETARCH} /app/server-card
# handleAuth 使用相对路径 "web/index.html" 读取，必须与二进制同级目录
COPY dist/server/web /app/web

RUN chmod 0755 /app/server-card \
 && mkdir -p /data \
 && chown -R opencert:opencert /app /data

USER opencert

# 容器内必须监听 0.0.0.0（默认值为 127.0.0.1，仅本机可访问）
ENV SERVER_CARD_HOST=0.0.0.0 \
    SERVER_CARD_PORT=1027 \
    SERVER_CARD_DB_PATH=/data/server.db \
    SERVER_CARD_MASTER_KEY_FILE=/data/server.masterkey \
    SERVER_CARD_LOG_LEVEL=info

EXPOSE 1027

# 数据库与主密钥都在 /data 下，必须挂载卷才能持久化
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${SERVER_CARD_PORT}/api/health" >/dev/null 2>&1 || exit 1

CMD ["/app/server-card"]
