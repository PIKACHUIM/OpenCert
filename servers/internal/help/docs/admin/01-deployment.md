---
title: 部署与初始化
summary: 环境变量、主密钥、JWT 密钥、初始管理员、反向代理与 HTTPS、备份恢复
order: 10
---

# 部署与初始化

## 1. 构建产物

`scripts/build-server.sh` 会同时构建服务端与前端：

```
dist/server/
├── server-card-linux-amd64
├── server-card-linux-arm64
├── web/            # 门户 + 控制台前端（与二进制同级）
└── SHA256SUMS
```

服务端通过 `SERVER_CARD_WEB_ROOT` 指定前端目录，缺省读取二进制同级的 `web/`。所有非 `/api`、`/crl`、`/ocsp`、`/ca`、`/pki`、`/acme`、`/ct` 的路径都会回退到前端入口页，支持刷新深链接。

## 2. 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `SERVER_CARD_HOST` | 生产必填 | 监听地址。`127.0.0.1` 视为开发环境；其它地址视为生产环境并启用安全基线 |
| `SERVER_CARD_PORT` | 否 | 监听端口，默认 `1027` |
| `SERVER_CARD_BASE_URL` | 生产必填 | 对外访问地址（如 `https://pki.example.com`），用于生成支付回调地址 |
| `SERVER_CARD_JWT_SECRET` | 生产必填 | 至少 32 位随机字符串。**生产环境使用缺省值会拒绝启动** |
| `SERVER_CARD_JWT_EXPIRY_HOURS` | 否 | 登录令牌有效期（小时），默认 24 |
| `SERVER_CARD_MASTER_KEY` | 生产必填 | Base64 编码的 32 字节主密钥，用于加密 CA 私钥、证书私钥、PIN/PUK 与支付配置 |
| `SERVER_CARD_MASTER_KEY_FILE` | 否 | 主密钥文件路径（文件权限需为 0600），未设置环境变量时使用 |
| `SERVER_CARD_ADMIN_PASSWORD` | 建议 | 首次启动创建 `admin` 时的初始口令（至少 12 位） |
| `SERVER_CARD_DB_PATH` | 否 | SQLite 数据库路径 |
| `DATABASE_URL` | 否 | 使用 PostgreSQL/MySQL 时的连接串 |
| `SERVER_CARD_ALLOWED_ORIGINS` | 否 | 允许的跨域来源（逗号分隔）；同域部署无需设置 |
| `SERVER_CARD_WEB_ROOT` | 否 | 前端静态资源目录 |
| `SERVER_CARD_SMTP_*` | 建议 | 邮件发送（找回密码、邮箱验证码），`ENABLED/HOST/PORT/USERNAME/PASSWORD/FROM/FROM_NAME/TLS` |
| `SERVER_CARD_CT_SUBMIT_TOKEN` | 否 | 证书透明度提交接口的访问令牌 |
| `SERVER_CARD_LOG_LEVEL` | 否 | 日志级别：debug/info/warn/error |

生成密钥示例：

```bash
# 32 字节主密钥（Base64）
openssl rand -base64 32
# JWT 密钥
openssl rand -base64 48
```

> **主密钥一旦丢失，所有加密数据（CA 私钥、证书私钥、卡片 PIN）将无法解密。**请离线备份，并与数据库备份分开保存。

## 3. 初始管理员

首次启动时若不存在 `admin` 账号会自动创建：

- 设置了 `SERVER_CARD_ADMIN_PASSWORD`：使用该口令；
- 生产环境未设置：生成随机口令，**仅在首次启动日志中输出一次**；
- 开发环境（`127.0.0.1`）：口令为 `admin`。

登录后请立即：

1. 修改管理员密码；
2. 在「个人中心」绑定两步验证；
3. 在「用户管理」为其他管理员创建独立账号，避免共用 `admin`。

## 4. 反向代理与 HTTPS

生产环境必须通过 HTTPS 对外提供服务（云端智能卡客户端默认拒绝非 HTTPS 连接）。Nginx 示例：

```nginx
server {
    listen 443 ssl http2;
    server_name pki.example.com;
    ssl_certificate     /etc/ssl/pki.crt;
    ssl_certificate_key /etc/ssl/pki.key;
    client_max_body_size 5m;

    location / {
        proxy_pass http://127.0.0.1:1027;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

注意：CRL/OCSP/CA 下载地址按请求的 Host 生成，代理必须透传 `Host` 头。

## 5. 备份与恢复

| 对象 | 频率 | 说明 |
|---|---|---|
| 数据库 | 每日 + 变更前 | SQLite 可在低峰期复制 `.db`、`.db-wal`、`.db-shm`；外部数据库使用其原生备份 |
| 主密钥 | 一次性 | 离线保存，多人分持 |
| 前端与二进制 | 每个版本 | 保留 `SHA256SUMS` 用于校验 |

恢复演练：在隔离环境用备份数据库 + 主密钥启动，验证能登录、能查看证书、能完成一次签名。

## 6. 国密算法支持范围

平台内置国密实现，无需额外安装国密库。

| 环节 | 说明 |
|---|---|
| CA | 创建或导入 SM2 CA；签名算法固定为 SM2WithSM3 |
| 签发 | 证书、CRL、OCSP 响应均支持 SM2 签名 |
| 云卡 | 云端私钥支持 SM2WithSM3 签名 |
| 客户端 | 本地智能卡支持 SM2 生成/签名/验签/加解密、SM3 摘要、SM4 加解密；本地 CSR、自签、本地 CA、证书导入导出均支持 SM2 |
| PKCS#11 驱动 | 开放 SM2/SM3/SM4 机制，第三方应用可通过驱动使用国密证书；SM4 密钥以 CKO_SECRET_KEY 对象导入（仅会话内有效，不落盘），支持 CBC / GCM |
| 门户与接口 | 算法选择中会标出国密项，SM2 只能配 SM3 |

限制：

- Windows 系统证书存储（CNG/KSP）没有国密算法标识，KSP 不枚举 SM2 密钥；客户端注册系统证书时会跳过 SM2 证书，国密证书请通过 PKCS#11 驱动使用；
- TPM 类卡片不支持国密算法，相关操作会返回"机制不支持"；
- SM2 证书不提供 PKCS#12 导出，请使用 PEM / PKCS#8。

## 7. 系统邮件

- 系统邮件的接口在「系统设置 → 系统邮件」中选择，未选择时使用本机环境变量中的 SMTP 配置；
- 邮件接口的完整配置（SMTP / Resend）在「证书颁发管理 → 身份认证审核 → 邮件」中维护；
- 更换默认接口后建议先发送一封测试邮件，确认发件人与连通性正常。
