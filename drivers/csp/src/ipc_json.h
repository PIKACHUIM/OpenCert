/*
 * ipc_json.h — 轻量级 JSON 构建/解析辅助工具
 *
 * 不依赖任何第三方 JSON 库，仅使用标准 C 字符串操作。
 * 用于构建 IPC 请求 JSON 和解析响应 JSON 中的关键字段。
 */

#ifndef IPC_JSON_H
#define IPC_JSON_H

#include <stdint.h>
#include <stddef.h>

/* ---- JSON 构建器 ---- */

/**
 * json_buf_t - 动态增长的字符串缓冲区，用于构建 JSON。
 */
typedef struct {
    char    *buf;
    size_t   len;
    size_t   cap;
} json_buf_t;

/** 初始化 JSON 缓冲区（初始容量 256 字节）*/
void json_buf_init(json_buf_t *jb);

/** 释放 JSON 缓冲区 */
void json_buf_free(json_buf_t *jb);

/** 追加字符串 */
int json_buf_append(json_buf_t *jb, const char *s);

/** 追加格式化字符串 */
int json_buf_appendf(json_buf_t *jb, const char *fmt, ...);

/** 追加 base64 编码的二进制数据（作为 JSON 字符串值）*/
int json_buf_append_b64(json_buf_t *jb, const uint8_t *data, size_t len);

/* ---- JSON 解析辅助 ---- */

/**
 * json_get_uint32 - 从 JSON 字符串中提取 uint32 字段值。
 * 例如：json_get_uint32("{\"rv\":0}", "rv") → 0
 * 返回 0 成功，-1 字段不存在。
 */
int json_get_uint32(const char *json, const char *key, uint32_t *out);

/**
 * json_get_string - 从 JSON 字符串中提取字符串字段值（去除引号）。
 * 调用者负责 free 返回的字符串。
 * 返回 NULL 表示字段不存在。
 */
char *json_get_string(const char *json, const char *key);

/**
 * json_get_b64 - 从 JSON 字符串中提取 base64 字段并解码。
 * @out_data: 输出缓冲区（调用者负责 free）
 * @out_len:  输出数据长度
 * 返回 0 成功，-1 失败。
 */
int json_get_b64(const char *json, const char *key,
                 uint8_t **out_data, size_t *out_len);

/* ---- Base64 编解码 ---- */

/**
 * b64_encode - 将二进制数据编码为 base64 字符串。
 * 返回 NULL 终止的字符串（调用者负责 free）。
 */
char *b64_encode(const uint8_t *data, size_t len);

/**
 * b64_decode - 将 base64 字符串解码为二进制数据。
 * @out_len: 输出数据长度
 * 返回解码后的数据（调用者负责 free），失败返回 NULL。
 */
uint8_t *b64_decode(const char *s, size_t *out_len);

/* ---- 兼容别名 ---- */

/** base64_encode / base64_decode 是 b64_encode / b64_decode 的别名 */
#define base64_encode(data, len)   b64_encode((data), (len))
#define base64_decode(s, out_len)  b64_decode((s), (out_len))

/**
 * json_get_int - 从 JSON 字符串中提取整数字段值，字段不存在时返回默认值。
 * 例如：json_get_int("{\"major\":2}", "major", 0) → 2
 */
int json_get_int(const char *json, const char *key, int default_val);

#endif /* IPC_JSON_H */
