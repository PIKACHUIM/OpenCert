---
title: 支付插件
summary: 多支付插件配置、留空运行、回调地址、热加载，以及新增支付渠道的开发接口
order: 50
---

# 支付插件

入口：**商品与交易 → 支付插件配置**。

## 1. 可以不配置任何插件

支付插件是**可选**的。未启用任何插件时：

- 收银台只显示「账户余额」（金额为 0 的订单直接完成）；
- 客户线下转账后，由管理员在「销售订单管理」中**确认到账**；
- 其余流程（申请、审核、签发、开卡）完全不受影响。

## 2. 支持的插件与配置键

创建插件时在「配置」中填写对应键值（JSON 字段名），密钥使用主密钥加密存储，列表接口不会返回任何密钥内容。

| 类型 | 配置键 |
|---|---|
| `alipay` 支付宝 | `app_id`、`private_key`、`alipay_pubkey`，可选 `gateway`、`sandbox` |
| `wechat` 微信支付 | `mch_id`、`app_id`、`serial_no`、`private_key`、`api_v3_key`、`platform_cert`，可选 `gateway` |
| `stripe` | `secret_key`、`webhook_secret`，可选 `currency`、`gateway` |
| `paypal` | `client_id`、`client_secret`、`webhook_id`，可选 `currency`、`sandbox`、`gateway` |

- 以**启用**状态保存时会立即校验配置，配置不完整会被拒绝；可先以**停用**状态保存草稿；
- 增、删、启停后**立即热加载**，无需重启服务；停用或删除的插件会立刻停止收款；
- 同一类型启用了多个插件时，按「排序权重」取最高的一个生效；
- 修改密钥：删除旧插件后重新创建。

## 3. 回调地址

在渠道后台配置异步通知地址：

```
https://<SERVER_CARD_BASE_URL>/api/payment/callback/<插件类型>
例如：https://pki.example.com/api/payment/callback/alipay
```

服务端处理回调时会：

1. 按渠道规则验签；
2. 按（订单号，渠道）匹配支付尝试，并核对**金额**；
3. 以条件更新完成入账，重复回调幂等返回成功；
4. 已关闭的尝试收到成功回调时拒绝入账并保留原文，待人工对账。

## 4. 新增支付渠道（开发接口）

新渠道只需实现 `payment.PaymentProvider` 接口：

```go
type PaymentProvider interface {
    Name() string
    Type() string
    CreateOrder(ctx context.Context, req CreateOrderReq) (*CreateOrderResp, error)
    QueryOrder(ctx context.Context, orderNo string) (*QueryOrderResp, error)
    VerifyCallback(ctx context.Context, body []byte, headers map[string]string) (*CallbackData, error)
    Refund(ctx context.Context, req RefundReq) (*RefundResp, error)
}
```

并在包初始化时注册工厂：

```go
func init() {
    payment.RegisterFactory("unionpay", func(raw []byte) (payment.PaymentProvider, error) {
        return NewUnionPayProvider(raw)
    })
}
```

之后在管理端创建 `plugin_type = unionpay` 的插件即可使用，收银台、回调、退款代码无需修改。实现要求：

- `VerifyCallback` 必须验签，并返回渠道回调中的**真实金额**（分）；
- `Refund` 只有渠道明确成功才返回 `success`，处理中返回 `pending`，失败返回 `failed` 或错误；
- 不要在日志中输出密钥与完整回调报文中的敏感字段。
