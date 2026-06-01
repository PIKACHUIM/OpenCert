/*
 * opencert_fido.h - OpenCert FIDO2 CCID 虚拟智能卡
 *
 * 实现 FIDO2 CTAP2 over CCID 协议，通过 IPC 将认证请求转发给 client-card 后端。
 * 私钥存储在 OpenCert 智能卡（本地/TPM/云端），Windows 仅作为传输层。
 *
 * 架构：
 *   浏览器 → Windows WebAuthn → CCID驱动 → 本DLL → IPC → client-card(Go)
 *
 * 参考：
 *   FIDO CTAP2 Spec: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
 *   ISO 7816-4 APDU: https://www.iso.org/standard/54550.html
 */

#ifndef OPENCERT_FIDO_H
#define OPENCERT_FIDO_H

#include <windows.h>
#include <winscard.h>
#include <stdint.h>

/* ================================================================
 * FIDO2 CTAP2 命令码
 * ================================================================ */
#define CTAP2_CMD_MAKE_CREDENTIAL       0x01u
#define CTAP2_CMD_GET_ASSERTION         0x02u
#define CTAP2_CMD_GET_INFO              0x04u
#define CTAP2_CMD_CLIENT_PIN            0x06u
#define CTAP2_CMD_RESET                 0x07u
#define CTAP2_CMD_GET_NEXT_ASSERTION    0x08u
#define CTAP2_CMD_SELECTION             0x0Bu
#define CTAP2_CMD_LARGE_BLOBS           0x0Cu
#define CTAP2_CMD_CONFIG                0x0Du

/* ================================================================
 * CTAP2 状态码
 * ================================================================ */
#define CTAP2_OK                        0x00u
#define CTAP1_ERR_INVALID_COMMAND       0x01u
#define CTAP1_ERR_INVALID_PARAMETER     0x02u
#define CTAP1_ERR_INVALID_LENGTH        0x03u
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE  0x11u
#define CTAP2_ERR_INVALID_CBOR          0x12u
#define CTAP2_ERR_MISSING_PARAMETER     0x14u
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26u
#define CTAP2_ERR_INVALID_CREDENTIAL    0x22u
#define CTAP2_ERR_USER_ACTION_PENDING   0x23u
#define CTAP2_ERR_OPERATION_PENDING     0x24u
#define CTAP2_ERR_NO_CREDENTIALS        0x2Eu
#define CTAP2_ERR_USER_ACTION_TIMEOUT   0x2Fu
#define CTAP2_ERR_NOT_ALLOWED           0x30u
#define CTAP2_ERR_PIN_INVALID           0x31u
#define CTAP2_ERR_PIN_BLOCKED           0x32u
#define CTAP2_ERR_PIN_AUTH_INVALID      0x33u
#define CTAP2_ERR_PIN_NOT_SET           0x35u
#define CTAP2_ERR_PIN_REQUIRED          0x36u
#define CTAP2_ERR_REQUEST_TOO_LARGE     0x39u
#define CTAP2_ERR_ACTION_TIMEOUT        0x3Au
#define CTAP2_ERR_UP_REQUIRED           0x3Bu
#define CTAP1_ERR_OTHER                 0x7Fu
#define CTAP2_ERR_SPEC_LAST             0xDFu
#define CTAP2_ERR_EXTENSION_FIRST       0xE0u
#define CTAP2_ERR_VENDOR_FIRST          0xF0u

/* ================================================================
 * CCID/APDU 常量
 * ================================================================ */

/* FIDO2 Applet AID: A0 00 00 06 47 2F 00 01 */
#define FIDO_AID_LEN                    8u
static const BYTE FIDO_AID[FIDO_AID_LEN] = {
    0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
};

/* APDU 指令字节 */
#define APDU_CLA_ISO                    0x00u
#define APDU_CLA_FIDO                   0x80u
#define APDU_INS_SELECT                 0xA4u
#define APDU_INS_FIDO2                  0x10u  /* CTAP2 命令通道 */
#define APDU_INS_NFCCTAP_MSG            0x10u  /* NFC CTAP 消息 */

/* APDU 状态字 */
#define APDU_SW_SUCCESS                 0x9000u
#define APDU_SW_CONDITIONS_NOT_SATISFIED 0x6985u
#define APDU_SW_WRONG_DATA              0x6A80u
#define APDU_SW_WRONG_LENGTH            0x6700u
#define APDU_SW_INS_NOT_SUPPORTED       0x6D00u
#define APDU_SW_CLA_NOT_SUPPORTED       0x6E00u
#define APDU_SW_UNKNOWN                 0x6F00u

/* APDU 缓冲区最大长度（扩展 APDU：65535 + 7 字节头） */
#define APDU_MAX_LEN                    65542u
#define APDU_RESP_MAX_LEN               65536u

/* ================================================================
 * CBOR 类型标记（简化实现，仅用于构造响应）
 * ================================================================ */
#define CBOR_UINT                       0x00u
#define CBOR_NEGINT                     0x20u
#define CBOR_BYTES                      0x40u
#define CBOR_TEXT                       0x60u
#define CBOR_ARRAY                      0x80u
#define CBOR_MAP                        0xA0u
#define CBOR_TAG                        0xC0u
#define CBOR_SIMPLE                     0xE0u
#define CBOR_FALSE                      0xF4u
#define CBOR_TRUE                       0xF5u
#define CBOR_NULL                       0xF6u

/* ================================================================
 * authenticatorData flags
 * ================================================================ */
#define AUTHDATA_FLAG_UP                0x01u  /* User Present */
#define AUTHDATA_FLAG_UV                0x04u  /* User Verified */
#define AUTHDATA_FLAG_BE                0x08u  /* Backup Eligibility */
#define AUTHDATA_FLAG_BS                0x10u  /* Backup State */
#define AUTHDATA_FLAG_AT                0x40u  /* Attested Credential Data */
#define AUTHDATA_FLAG_ED                0x80u  /* Extension Data */

/* ================================================================
 * AAGUID：OpenCert FIDO2 认证器标识
 * 格式：{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
 * ================================================================ */
#define OPENCERT_AAGUID_LEN             16u
static const BYTE OPENCERT_AAGUID[OPENCERT_AAGUID_LEN] = {
    /* OpenCert FIDO2 Authenticator: 4F70656E-4365-7274-4649-444F32303234 */
    0x4F, 0x70, 0x65, 0x6E, 0x43, 0x65, 0x72, 0x74,
    0x46, 0x49, 0x44, 0x4F, 0x32, 0x30, 0x32, 0x34
};

/* ================================================================
 * IPC 命令码（与 Go 侧 protocol.go 保持一致）
 * ================================================================ */
#define CMD_FIDO_GET_INFO               0x0300u
#define CMD_FIDO_MAKE_CREDENTIAL        0x0301u
#define CMD_FIDO_GET_ASSERTION          0x0302u
#define CMD_FIDO_CANCEL                 0x0303u
#define CMD_FIDO_LOGIN                  0x0304u

/* ================================================================
 * 内部数据结构
 * ================================================================ */

/* FIDO CCID 设备上下文 */
typedef struct _FIDO_DEVICE_CTX {
    DWORD       dwMagic;        /* 魔数校验 */
    BOOL        bSelected;      /* Applet 是否已 SELECT */
    HANDLE      hIpcPipe;       /* IPC Named Pipe 句柄 */
    BYTE        bPinVerified;   /* PIN 是否已验证 */
    DWORD       dwCardUUID[4];  /* 当前卡片 UUID（128位） */
} FIDO_DEVICE_CTX;

#define FIDO_CTX_MAGIC  0x46494432u  /* "FID2" */

/* APDU 命令结构 */
typedef struct _APDU_CMD {
    BYTE    bCLA;
    BYTE    bINS;
    BYTE    bP1;
    BYTE    bP2;
    DWORD   dwLc;       /* 命令数据长度（0 = 无数据） */
    BYTE   *pbData;     /* 命令数据指针 */
    DWORD   dwLe;       /* 期望响应长度（0 = 不期望数据） */
} APDU_CMD;

/* APDU 响应结构 */
typedef struct _APDU_RESP {
    BYTE   *pbData;     /* 响应数据（调用方负责 free） */
    DWORD   dwLen;      /* 响应数据长度 */
    WORD    wSW;        /* 状态字 */
} APDU_RESP;

/* ================================================================
 * 函数声明
 * ================================================================ */

/* DLL 入口 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

/* APDU 处理入口 */
LONG WINAPI FidoTransmit(
    SCARDHANDLE hCard,
    LPCSCARD_IO_REQUEST pioSendPci,
    LPCBYTE pbSendBuffer,
    DWORD cbSendLength,
    LPSCARD_IO_REQUEST pioRecvPci,
    LPBYTE pbRecvBuffer,
    LPDWORD pcbRecvLength
);

/* 内部 APDU 处理函数 */
static LONG fido_handle_apdu(
    FIDO_DEVICE_CTX *ctx,
    const APDU_CMD  *cmd,
    APDU_RESP       *resp
);

static LONG fido_handle_select(
    FIDO_DEVICE_CTX *ctx,
    const APDU_CMD  *cmd,
    APDU_RESP       *resp
);

static LONG fido_handle_ctap2(
    FIDO_DEVICE_CTX *ctx,
    const APDU_CMD  *cmd,
    APDU_RESP       *resp
);

/* CTAP2 命令处理 */
static LONG ctap2_get_info(
    FIDO_DEVICE_CTX *ctx,
    const BYTE      *cbor_req,
    DWORD            cbor_len,
    APDU_RESP       *resp
);

static LONG ctap2_make_credential(
    FIDO_DEVICE_CTX *ctx,
    const BYTE      *cbor_req,
    DWORD            cbor_len,
    APDU_RESP       *resp
);

static LONG ctap2_get_assertion(
    FIDO_DEVICE_CTX *ctx,
    const BYTE      *cbor_req,
    DWORD            cbor_len,
    APDU_RESP       *resp
);

/* IPC 辅助 */
static HANDLE fido_ipc_connect(void);
static int    fido_ipc_call(HANDLE hPipe, DWORD cmd,
                             const char *req_json,
                             char **resp_json, DWORD *out_rv);

/* CBOR 辅助（最小化实现） */
static DWORD cbor_encode_uint(BYTE *buf, DWORD buflen, uint64_t val);
static DWORD cbor_encode_bytes(BYTE *buf, DWORD buflen, const BYTE *data, DWORD datalen);
static DWORD cbor_encode_text(BYTE *buf, DWORD buflen, const char *str);
static DWORD cbor_encode_map_header(BYTE *buf, DWORD buflen, DWORD count);
static DWORD cbor_encode_array_header(BYTE *buf, DWORD buflen, DWORD count);
static DWORD cbor_encode_bool(BYTE *buf, DWORD buflen, BOOL val);

/* Base64 辅助 */
static char  *base64_encode(const BYTE *data, DWORD len);
static BYTE  *base64_decode(const char *str, DWORD *out_len);

/* JSON 辅助（轻量级，避免引入第三方库） */
static const char *json_get_string(const char *json, const char *key, char *out, DWORD outlen);
static const char *json_get_bytes_b64(const char *json, const char *key, BYTE **out, DWORD *outlen);

#endif /* OPENCERT_FIDO_H */
