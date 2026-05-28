/*
 * ipc_client.c — pkcs11-mock IPC 客户端实现
 *
 * 跨平台：
 *   Windows  → Named Pipe  \\.\pipe\pkcs11-client-card
 *   macOS/Linux → Unix Domain Socket /tmp/pkcs11-client-card.sock
 *
 * 协议：Magic(4B,BE) + Cmd(4B,BE) + Len(4B,BE) + JSON Payload
 */

#include "ipc_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- 平台相关头文件 ---- */
#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <time.h>
#  include <unistd.h>
#endif

/* ---- 全局连接句柄 ---- */
static ipc_fd_t g_fd = IPC_INVALID_FD;

/* ================================================================
 * 平台相关：字节序转换（大端）
 * ================================================================ */

static uint32_t u32_to_be(uint32_t v)
{
#ifdef _WIN32
    return _byteswap_ulong(v);
#else
    /* 检测本机字节序 */
    static const uint32_t test = 1;
    if (*(const uint8_t *)&test == 0) {
        return v; /* 已是大端 */
    }
    return ((v & 0xFF000000u) >> 24) |
           ((v & 0x00FF0000u) >>  8) |
           ((v & 0x0000FF00u) <<  8) |
           ((v & 0x000000FFu) << 24);
#endif
}

static uint32_t be_to_u32(uint32_t v)
{
    return u32_to_be(v); /* 对称操作 */
}

/* ================================================================
 * 平台相关：底层读写
 * ================================================================ */

static int raw_write(ipc_fd_t fd, const void *buf, uint32_t len)
{
#ifdef _WIN32
    DWORD written = 0;
    const char *p = (const char *)buf;
    uint32_t remaining = len;
    while (remaining > 0) {
        if (!WriteFile(fd, p, remaining, &written, NULL))
            return -1;
        p += written;
        remaining -= written;
    }
    return 0;
#else
    const char *p = (const char *)buf;
    uint32_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0) return -1;
        p += n;
        remaining -= (uint32_t)n;
    }
    return 0;
#endif
}

static int raw_read(ipc_fd_t fd, void *buf, uint32_t len)
{
#ifdef _WIN32
    DWORD read_bytes = 0;
    char *p = (char *)buf;
    uint32_t remaining = len;
    while (remaining > 0) {
        if (!ReadFile(fd, p, remaining, &read_bytes, NULL) || read_bytes == 0)
            return -1;
        p += read_bytes;
        remaining -= read_bytes;
    }
    return 0;
#else
    char *p = (char *)buf;
    uint32_t remaining = len;
    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n <= 0) return -1;
        p += n;
        remaining -= (uint32_t)n;
    }
    return 0;
#endif
}

/* ================================================================
 * 平台相关：连接 / 断开
 * ================================================================ */

#ifdef _WIN32

static ipc_fd_t platform_connect(void)
{
    HANDLE h = CreateFileA(
        IPC_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        0, NULL
    );
    if (h == INVALID_HANDLE_VALUE)
        return IPC_INVALID_FD;

    /* 设置字节模式（非消息模式）*/
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(h, &mode, NULL, NULL);
    return h;
}

static void platform_disconnect(ipc_fd_t fd)
{
    if (fd != IPC_INVALID_FD)
        CloseHandle(fd);
}

static void platform_sleep_ms(int ms)
{
    Sleep((DWORD)ms);
}

#else /* POSIX */

static ipc_fd_t platform_connect(void)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return IPC_INVALID_FD;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return IPC_INVALID_FD;
    }
    return sock;
}

static void platform_disconnect(ipc_fd_t fd)
{
    if (fd != IPC_INVALID_FD)
        close(fd);
}

static void platform_sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

#endif /* _WIN32 */

/* ================================================================
 * 公共接口实现
 * ================================================================ */

ipc_fd_t ipc_connect(int retry_count, int retry_ms)
{
    int i;
    for (i = 0; i <= retry_count; i++) {
        ipc_fd_t fd = platform_connect();
        if (fd != IPC_INVALID_FD)
            return fd;
        if (i < retry_count)
            platform_sleep_ms(retry_ms);
    }
    return IPC_INVALID_FD;
}

void ipc_disconnect(ipc_fd_t fd)
{
    platform_disconnect(fd);
}

int ipc_is_connected(ipc_fd_t fd)
{
    return fd != IPC_INVALID_FD;
}

int ipc_send_frame(ipc_fd_t fd, uint32_t cmd, const char *payload, uint32_t len)
{
    uint8_t header[IPC_HEADER_SIZE];
    uint32_t magic_be = u32_to_be(IPC_MAGIC);
    uint32_t cmd_be   = u32_to_be(cmd);
    uint32_t len_be   = u32_to_be(len);

    memcpy(header + 0, &magic_be, 4);
    memcpy(header + 4, &cmd_be,   4);
    memcpy(header + 8, &len_be,   4);

    if (raw_write(fd, header, IPC_HEADER_SIZE) != 0)
        return -1;

    if (len > 0 && payload != NULL) {
        if (raw_write(fd, payload, len) != 0)
            return -1;
    }
    return 0;
}

int ipc_recv_frame(ipc_fd_t fd, uint32_t *out_cmd, char **out_buf, uint32_t *out_len)
{
    uint8_t header[IPC_HEADER_SIZE];
    uint32_t magic, cmd, len;

    if (raw_read(fd, header, IPC_HEADER_SIZE) != 0)
        return -1;

    memcpy(&magic, header + 0, 4); magic = be_to_u32(magic);
    memcpy(&cmd,   header + 4, 4); cmd   = be_to_u32(cmd);
    memcpy(&len,   header + 8, 4); len   = be_to_u32(len);

    if (magic != IPC_MAGIC)
        return -1;

    if (len > IPC_MAX_PAYLOAD)
        return -1;

    *out_cmd = cmd;
    *out_len = len;
    *out_buf = NULL;

    if (len > 0) {
        *out_buf = (char *)malloc(len + 1);
        if (*out_buf == NULL)
            return -1;

        if (raw_read(fd, *out_buf, len) != 0) {
            free(*out_buf);
            *out_buf = NULL;
            return -1;
        }
        (*out_buf)[len] = '\0'; /* 确保 NULL 终止 */
    }
    return 0;
}

int ipc_call(ipc_fd_t fd, uint32_t cmd,
             const char *req_json,
             char **resp_json, uint32_t *out_rv)
{
    uint32_t req_len = req_json ? (uint32_t)strlen(req_json) : 0;

    /* 发送请求 */
    if (ipc_send_frame(fd, cmd, req_json, req_len) != 0)
        return -1;

    /* 接收响应 */
    uint32_t resp_cmd = 0;
    char *resp_buf = NULL;
    uint32_t resp_len = 0;

    if (ipc_recv_frame(fd, &resp_cmd, &resp_buf, &resp_len) != 0)
        return -1;

    /* 解析 rv 字段：{"rv":0,"data":...} */
    *out_rv = IPC_CKR_GENERAL_ERROR;
    if (resp_buf != NULL) {
        /* 简单解析 rv 字段（避免引入 JSON 库依赖）*/
        const char *rv_pos = strstr(resp_buf, "\"rv\":");
        if (rv_pos != NULL) {
            *out_rv = (uint32_t)strtoul(rv_pos + 5, NULL, 10);
        }
        if (resp_json != NULL) {
            *resp_json = resp_buf; /* 转移所有权 */
        } else {
            free(resp_buf);
        }
    }
    return 0;
}

/* ================================================================
 * 全局连接（单例）+ 版本协商 + 心跳
 * ================================================================ */

/* 心跳失败计数 */
static int g_heartbeat_failures = 0;
#define MAX_HEARTBEAT_FAILURES 3

/**
 * ipc_handshake - 版本协商握手。
 * 连接成功后发送 CMD_HANDSHAKE + {"version":1}，
 * 检查响应中的 "compatible" 字段。
 * 返回 0 成功，-1 不兼容。
 */
static int ipc_handshake(ipc_fd_t fd)
{
    const char *req = "{\"version\":1}";
    char *resp = NULL;
    uint32_t rv = 0;

    int ret = ipc_call(fd, CMD_HANDSHAKE, req, &resp, &rv);
    if (ret != 0) {
        /* 通信失败，可能是旧版本服务端不支持握手，降级允许 */
        return 0;
    }

    if (rv != IPC_CKR_OK) {
        if (resp) free(resp);
        return -1; /* 服务端明确拒绝 */
    }

    /* 检查 compatible 字段 */
    int compatible = 1;
    if (resp != NULL) {
        const char *pos = strstr(resp, "\"compatible\":");
        if (pos != NULL) {
            /* 解析 true/false */
            pos += 13;
            while (*pos == ' ') pos++;
            if (*pos == 'f' || *pos == '0') {
                compatible = 0;
            }
        }
        free(resp);
    }

    return compatible ? 0 : -1;
}

/**
 * ipc_send_ping - 发送心跳 Ping。
 * 返回 0 成功，-1 失败。
 */
int ipc_send_ping(ipc_fd_t fd)
{
    char *resp = NULL;
    uint32_t rv = 0;
    int ret = ipc_call(fd, CMD_PING, NULL, &resp, &rv);
    if (resp) free(resp);
    return (ret == 0 && rv == IPC_CKR_OK) ? 0 : -1;
}

/**
 * ipc_check_heartbeat - 检查心跳，失败时尝试重连。
 * 返回 0 连接正常，-1 彻底断开。
 */
int ipc_check_heartbeat(void)
{
    if (g_fd == IPC_INVALID_FD)
        return -1;

    if (ipc_send_ping(g_fd) == 0) {
        g_heartbeat_failures = 0;
        return 0;
    }

    g_heartbeat_failures++;
    if (g_heartbeat_failures >= MAX_HEARTBEAT_FAILURES) {
        /* 3 次心跳失败，关闭连接并尝试重连 */
        ipc_global_disconnect();

        /* 指数退避重连：1s, 2s, 4s */
        int delays[] = {1000, 2000, 4000};
        int i;
        for (i = 0; i < 3; i++) {
            platform_sleep_ms(delays[i]);
            g_fd = platform_connect();
            if (g_fd != IPC_INVALID_FD) {
                /* 重连成功，重新握手 */
                if (ipc_handshake(g_fd) == 0) {
                    g_heartbeat_failures = 0;
                    return 0;
                }
                /* 握手失败，断开重试 */
                platform_disconnect(g_fd);
                g_fd = IPC_INVALID_FD;
            }
        }
        return -1; /* 重连失败 */
    }
    return 0; /* 还未达到阈值，暂时忽略 */
}

int ipc_global_connect(void)
{
    if (g_fd != IPC_INVALID_FD)
        return 0; /* 已连接 */

    /* 尝试连接，最多重试 5 次，每次间隔 500ms */
    g_fd = ipc_connect(5, 500);
    if (g_fd == IPC_INVALID_FD)
        return -1;

    /* 版本协商握手 */
    if (ipc_handshake(g_fd) != 0) {
        /* 版本不兼容，断开连接 */
        ipc_disconnect(g_fd);
        g_fd = IPC_INVALID_FD;
        return -1;
    }

    g_heartbeat_failures = 0;
    return 0;
}

void ipc_global_disconnect(void)
{
    if (g_fd != IPC_INVALID_FD) {
        ipc_disconnect(g_fd);
        g_fd = IPC_INVALID_FD;
    }
}

ipc_fd_t ipc_global_fd(void)
{
    return g_fd;
}
