/*
 * ipc_client.h — pkcs11-mock IPC 客户端
 *
 * 协议格式：Magic(4B,BE) + Cmd(4B,BE) + Len(4B,BE) + Payload(JSON)
 * 传输方式：Windows = Named Pipe，macOS/Linux = Unix Domain Socket
 *
 * 命令码与 client-card/internal/ipc/protocol.go 保持一致。
 */

#ifndef IPC_CLIENT_H
#define IPC_CLIENT_H

#include <stdint.h>

#ifdef _WIN32
#  include <windows.h>
   typedef HANDLE ipc_fd_t;
#  define IPC_INVALID_FD  INVALID_HANDLE_VALUE
#  define IPC_PIPE_NAME   "\\\\.\\pipe\\pkcs11-client-card"
#else
#  include <unistd.h>
   typedef int ipc_fd_t;
#  define IPC_INVALID_FD  (-1)
#  define IPC_SOCKET_PATH "/tmp/pkcs11-client-card.sock"
#endif

/* ---- 协议常量 ---- */
#define IPC_MAGIC          0x504B3131u  /* "PK11" */
#define IPC_HEADER_SIZE    12           /* Magic(4) + Cmd(4) + Len(4) */
#define IPC_MAX_PAYLOAD    (4 * 1024 * 1024)

/* ---- 命令码（与 Go 侧 protocol.go 一致）---- */
#define CMD_PING               0x0000u
#define CMD_GET_INFO           0x0001u
#define CMD_GET_SLOT_LIST      0x0002u
#define CMD_GET_SLOT_INFO      0x0003u
#define CMD_GET_TOKEN_INFO     0x0004u
#define CMD_GET_MECHANISM_LIST 0x0005u
#define CMD_GET_MECHANISM_INFO 0x0006u
#define CMD_OPEN_SESSION       0x0007u
#define CMD_CLOSE_SESSION      0x0008u
#define CMD_CLOSE_ALL_SESSIONS 0x0009u
#define CMD_LOGIN              0x000Au
#define CMD_LOGOUT             0x000Bu
#define CMD_FIND_OBJECTS_INIT  0x000Cu
#define CMD_FIND_OBJECTS       0x000Du
#define CMD_FIND_OBJECTS_FINAL 0x000Eu
#define CMD_GET_ATTRIBUTE_VALUE 0x000Fu
#define CMD_SET_ATTRIBUTE_VALUE 0x0010u
#define CMD_CREATE_OBJECT      0x0011u
#define CMD_DESTROY_OBJECT     0x0012u
#define CMD_GET_OBJECT_SIZE    0x0013u
#define CMD_SIGN_INIT          0x0014u
#define CMD_SIGN               0x0015u
#define CMD_SIGN_UPDATE        0x0016u
#define CMD_SIGN_FINAL         0x0017u
#define CMD_VERIFY_INIT        0x0018u
#define CMD_VERIFY             0x0019u
#define CMD_DECRYPT_INIT       0x001Au
#define CMD_DECRYPT            0x001Bu
#define CMD_ENCRYPT_INIT       0x001Cu
#define CMD_ENCRYPT            0x001Du
#define CMD_GENERATE_KEY_PAIR  0x001Eu
#define CMD_GENERATE_RANDOM    0x001Fu
#define CMD_DIGEST_INIT        0x0020u
#define CMD_DIGEST             0x0021u
#define CMD_GET_SESSION_INFO   0x0022u
#define CMD_INIT_PIN           0x0023u
#define CMD_SET_PIN            0x0024u
/* 流式 Digest / Verify 与 SeedRandom（v1.1 扩展） */
#define CMD_DIGEST_UPDATE      0x0025u
#define CMD_DIGEST_KEY         0x0026u
#define CMD_DIGEST_FINAL       0x0027u
#define CMD_VERIFY_UPDATE      0x0028u
#define CMD_VERIFY_FINAL       0x0029u
#define CMD_SEED_RANDOM        0x002Au
#define CMD_HANDSHAKE          0x00FFu

/* ---- CK_RV 常用返回码 ---- */
#define IPC_CKR_OK                    0x00000000u
#define IPC_CKR_GENERAL_ERROR         0x00000005u
#define IPC_CKR_DEVICE_ERROR          0x00000030u
#define IPC_CKR_DEVICE_REMOVED        0x00000031u

/* ---- IPC 帧结构 ---- */
typedef struct {
    uint32_t magic;
    uint32_t cmd;
    uint32_t len;
} ipc_header_t;

/* ---- 连接管理 ---- */

/**
 * ipc_connect - 连接到 client-card IPC 服务。
 * 返回有效的文件描述符/句柄，失败返回 IPC_INVALID_FD。
 * 支持重试：最多尝试 retry_count 次，每次间隔 retry_ms 毫秒。
 */
ipc_fd_t ipc_connect(int retry_count, int retry_ms);

/**
 * ipc_disconnect - 关闭 IPC 连接。
 */
void ipc_disconnect(ipc_fd_t fd);

/**
 * ipc_is_connected - 检查连接是否有效。
 */
int ipc_is_connected(ipc_fd_t fd);

/* ---- 帧读写 ---- */

/**
 * ipc_send_frame - 发送一个 IPC 帧。
 * @fd:      连接句柄
 * @cmd:     命令码
 * @payload: JSON payload（可为 NULL）
 * @len:     payload 长度
 * 返回 0 成功，-1 失败。
 */
int ipc_send_frame(ipc_fd_t fd, uint32_t cmd, const char *payload, uint32_t len);

/**
 * ipc_recv_frame - 接收一个 IPC 帧。
 * @fd:         连接句柄
 * @out_cmd:    输出命令码
 * @out_buf:    输出 payload 缓冲区（调用者负责 free）
 * @out_len:    输出 payload 长度
 * 返回 0 成功，-1 失败。
 */
int ipc_recv_frame(ipc_fd_t fd, uint32_t *out_cmd, char **out_buf, uint32_t *out_len);

/* ---- 高层 RPC 调用 ---- */

/**
 * ipc_call - 发送请求并接收响应（同步 RPC）。
 * @fd:          连接句柄
 * @cmd:         命令码
 * @req_json:    请求 JSON 字符串（可为 NULL）
 * @resp_json:   输出响应 JSON 字符串（调用者负责 free，可为 NULL）
 * @out_rv:      输出 CK_RV 返回码
 * 返回 0 成功，-1 通信失败。
 */
int ipc_call(ipc_fd_t fd, uint32_t cmd,
             const char *req_json,
             char **resp_json, uint32_t *out_rv);

/* ---- 全局连接（单例）---- */

/**
 * ipc_global_connect - 初始化全局连接（C_Initialize 时调用）。
 */
int ipc_global_connect(void);

/**
 * ipc_global_disconnect - 断开全局连接（C_Finalize 时调用）。
 */
void ipc_global_disconnect(void);

/**
 * ipc_global_fd - 获取全局连接句柄。
 */
ipc_fd_t ipc_global_fd(void);

/* ---- 心跳与版本协商 ---- */

/**
 * ipc_send_ping - 发送心跳 Ping。
 * 返回 0 成功，-1 失败。
 */
int ipc_send_ping(ipc_fd_t fd);

/**
 * ipc_check_heartbeat - 检查心跳，失败时尝试重连（指数退避）。
 * 返回 0 连接正常，-1 彻底断开。
 */
int ipc_check_heartbeat(void);

#endif /* IPC_CLIENT_H */
