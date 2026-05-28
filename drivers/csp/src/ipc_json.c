/*
 * ipc_json.c — 轻量级 JSON 构建/解析 + Base64 编解码实现
 */

#include "ipc_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ================================================================
 * JSON 缓冲区
 * ================================================================ */

void json_buf_init(json_buf_t *jb)
{
    jb->cap = 256;
    jb->len = 0;
    jb->buf = (char *)malloc(jb->cap);
    if (jb->buf) jb->buf[0] = '\0';
}

void json_buf_free(json_buf_t *jb)
{
    if (jb->buf) {
        free(jb->buf);
        jb->buf = NULL;
    }
    jb->len = jb->cap = 0;
}

static int json_buf_grow(json_buf_t *jb, size_t need)
{
    if (jb->len + need + 1 <= jb->cap)
        return 0;

    size_t new_cap = jb->cap * 2;
    while (new_cap < jb->len + need + 1)
        new_cap *= 2;

    char *new_buf = (char *)realloc(jb->buf, new_cap);
    if (!new_buf) return -1;
    jb->buf = new_buf;
    jb->cap = new_cap;
    return 0;
}

int json_buf_append(json_buf_t *jb, const char *s)
{
    size_t slen = strlen(s);
    if (json_buf_grow(jb, slen) != 0) return -1;
    memcpy(jb->buf + jb->len, s, slen + 1);
    jb->len += slen;
    return 0;
}

int json_buf_appendf(json_buf_t *jb, const char *fmt, ...)
{
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (n < 0) return -1;
    if ((size_t)n < sizeof(tmp)) {
        return json_buf_append(jb, tmp);
    }

    /* 需要更大缓冲区 */
    char *big = (char *)malloc((size_t)n + 1);
    if (!big) return -1;
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    int ret = json_buf_append(jb, big);
    free(big);
    return ret;
}

int json_buf_append_b64(json_buf_t *jb, const uint8_t *data, size_t len)
{
    char *encoded = b64_encode(data, len);
    if (!encoded) return -1;
    json_buf_append(jb, "\"");
    json_buf_append(jb, encoded);
    json_buf_append(jb, "\"");
    free(encoded);
    return 0;
}

/* ================================================================
 * JSON 解析辅助
 * ================================================================ */

int json_get_uint32(const char *json, const char *key, uint32_t *out)
{
    if (!json || !key || !out) return -1;

    /* 构造搜索模式："key": */
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);

    const char *pos = strstr(json, pattern);
    if (!pos) return -1;

    pos += strlen(pattern);
    /* 跳过空白 */
    while (*pos == ' ' || *pos == '\t') pos++;

    *out = (uint32_t)strtoul(pos, NULL, 10);
    return 0;
}

char *json_get_string(const char *json, const char *key)
{
    if (!json || !key) return NULL;

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);

    const char *pos = strstr(json, pattern);
    if (!pos) return NULL;

    pos += strlen(pattern);

    /* 找到结束引号（处理转义）*/
    const char *end = pos;
    while (*end && *end != '"') {
        if (*end == '\\') end++; /* 跳过转义字符 */
        if (*end) end++;
    }

    size_t slen = (size_t)(end - pos);
    char *result = (char *)malloc(slen + 1);
    if (!result) return NULL;
    memcpy(result, pos, slen);
    result[slen] = '\0';
    return result;
}

int json_get_b64(const char *json, const char *key,
                 uint8_t **out_data, size_t *out_len)
{
    char *s = json_get_string(json, key);
    if (!s) return -1;

    *out_data = b64_decode(s, out_len);
    free(s);
    return (*out_data != NULL) ? 0 : -1;
}

/* ================================================================
 * Base64 编解码
 * ================================================================ */

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const uint8_t *data, size_t len)
{
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char *out = (char *)malloc(out_len);
    if (!out) return NULL;

    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        out[j++] = B64_TABLE[(data[i] >> 2) & 0x3F];
        out[j++] = B64_TABLE[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)];
        out[j++] = B64_TABLE[((data[i+1] & 0x0F) << 2) | ((data[i+2] >> 6) & 0x03)];
        out[j++] = B64_TABLE[data[i+2] & 0x3F];
    }
    if (i < len) {
        out[j++] = B64_TABLE[(data[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            out[j++] = B64_TABLE[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)];
            out[j++] = B64_TABLE[(data[i+1] & 0x0F) << 2];
        } else {
            out[j++] = B64_TABLE[(data[i] & 0x03) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
    return out;
}

static int b64_char_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

uint8_t *b64_decode(const char *s, size_t *out_len)
{
    if (!s || !out_len) return NULL;

    size_t slen = strlen(s);
    if (slen % 4 != 0) return NULL;

    size_t max_out = (slen / 4) * 3;
    uint8_t *out = (uint8_t *)malloc(max_out + 1);
    if (!out) return NULL;

    size_t i, j = 0;
    for (i = 0; i < slen; i += 4) {
        int v0 = b64_char_val(s[i]);
        int v1 = b64_char_val(s[i+1]);
        int v2 = (s[i+2] == '=') ? 0 : b64_char_val(s[i+2]);
        int v3 = (s[i+3] == '=') ? 0 : b64_char_val(s[i+3]);

        if (v0 < 0 || v1 < 0) { free(out); return NULL; }

        out[j++] = (uint8_t)((v0 << 2) | (v1 >> 4));
        if (s[i+2] != '=') out[j++] = (uint8_t)((v1 << 4) | (v2 >> 2));
        if (s[i+3] != '=') out[j++] = (uint8_t)((v2 << 6) | v3);
    }

    *out_len = j;
    out[j] = '\0';
    return out;
}

/* ================================================================
 * 兼容函数
 * ================================================================ */

int json_get_int(const char *json, const char *key, int default_val)
{
    uint32_t val = 0;
    if (json_get_uint32(json, key, &val) == 0)
        return (int)val;
    return default_val;
}
