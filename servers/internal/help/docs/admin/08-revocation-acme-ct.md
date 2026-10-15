---
title: CRL、OCSP、ACME 与 CT
summary: 吊销服务与自定义路径、OCSP 响应、ACME 自动化签发配置、证书透明度记录
order: 80
---

# CRL、OCSP、ACME 与 CT

## 1. 缺省吊销服务地址

每个 CA 创建后即具备以下公开地址（按请求 Host 生成）：

| 服务 | 地址 |
|---|---|
| CA 证书（AIA） | `GET /ca/<CA UUID>` |
| CRL | `GET /crl/<CA UUID>` |
| OCSP | `GET/POST /ocsp/<CA UUID>` |

## 2. 自定义路径

入口：**服务配置 → 证书吊销服务**，为 CA 配置更友好的路径：

| 字段 | 说明 |
|---|---|
| 关联 CA | 目标 CA |
| 服务类型 | `crl` / `ocsp` / `caissuer` |
| 路径 | 例如 `root-g1`，对外地址变为 `/pki/crl/root-g1`、`/pki/ocsp/root-g1`、`/pki/ca/root-g1` |
| CRL 更新间隔 | 分钟，缺省 60 |
| 启用 | 停用后回退到缺省地址 |

配置后，门户「信任服务」页面会自动展示自定义地址。

**注意**：证书中写入的 CRL/OCSP 地址在签发时确定，修改路径不会改变已签发证书，旧地址需要长期保留可用。

## 3. OCSP 验证

```bash
openssl ocsp -issuer ca.pem -cert user.pem \
  -url https://pki.example.com/ocsp/<CA UUID> -resp_text
```

返回 `good` / `revoked` / `unknown`。

若需要**用单个签名证书统一响应多个 CA**（对外统一入口、OCSP 委托签名场景），请使用
**证书服务 → 证书OCSP服务**（地址 `/ocsp/r/{path}`），配置方法见《OCSP 响应服务与证书策略》。

## 4. ACME

入口：**证书服务 → 证书 ACME 服务**。

| 字段 | 说明 |
|---|---|
| 路径 | 前缀名，例如 `default`，目录地址为 `/acme/default/directory` |
| 关联 CA | ACME 签发使用的 CA |
| 颁发模板 | 签发参数（有效期缺省 90 天） |

客户端示例：

```bash
certbot certonly --server https://pki.example.com/acme/default/directory \
  --standalone -d www.example.com
acme.sh --issue --server https://pki.example.com/acme/default/directory \
  -d www.example.com --webroot /var/www/html
```

ACME 签发不经过商城订单，请只对可信网络或内部域名开放，或在反向代理上做访问控制。

## 5. 证书透明度（CT）

入口：**证书颁发 → 证书审计日志 → 证书透明度（CT）选项卡**（CT 记录与操作审计同属可审计证据，已合并到同一页面）。平台记录签发的证书用于审计；`POST /ct/submit` 需要携带 `SERVER_CARD_CT_SUBMIT_TOKEN`，`GET /ct/query` 可按证书哈希查询。
