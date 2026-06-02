/*
 * Ccid.c - OpenCert FIDO2 UMDF CCID/CTAP2 处理层
 *
 * 解析 ISO 7816 APDU 命令，将 CTAP2 请求通过 IPC 转发给 Go 后端，
 * 并将响应封装为 APDU 格式返回给 Windows PC/SC 框架。
 *
 * APDU 流程：
 *   1. SELECT FIDO Applet (AID: A0 00 00 06 47 2F 00 01)
 *      → 响应：FIDO_2_0 + 0x9000
 *
 *   2. CTAP2 命令 (CLA=0x80, INS=0x10)
 *      → 数据：[1字节CTAP2命令码][CBOR参数]
 *      → 通过 IPC 转发给 Go 后端
 *      → 响应：[1字节CTAP2状态码][CBOR响应] + 0x9000
 *
 * 参考：
 *   FIDO CTAP2 over NFC/CCID: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
 *   ISO 7816-4 APDU: https://www.iso.org/standard/54550.html
 */

#include "Driver.h"
#include <stdio.h>   /* _snprintf_s */

/* ================================================================
 * 内部辅助：Base64 编码（用于 CBOR 数据的 JSON 传输）
 * ================================================================ */
static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static ULONG
Base64Encode(
    _In_  const BYTE *data,
    _In_  ULONG       dataLen,
    _Out_ char       *outBuf,
    _In_  ULONG       outBufLen
)
{
    ULONG i, j = 0;
    ULONG needed = ((dataLen + 2) / 3) * 4 + 1;

    if (outBufLen < needed) return 0;

    for (i = 0; i + 2 < dataLen; i += 3) {
        outBuf[j++] = B64_TABLE[(data[i] >> 2) & 0x3F];
        outBuf[j++] = B64_TABLE[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)];
        outBuf[j++] = B64_TABLE[((data[i+1] & 0x0F) << 2) | ((data[i+2] >> 6) & 0x03)];
        outBuf[j++] = B64_TABLE[data[i+2] & 0x3F];
    }
    if (i < dataLen) {
        outBuf[j++] = B64_TABLE[(data[i] >> 2) & 0x3F];
        if (i + 1 < dataLen) {
            outBuf[j++] = B64_TABLE[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)];
            outBuf[j++] = B64_TABLE[(data[i+1] & 0x0F) << 2];
        } else {
            outBuf[j++] = B64_TABLE[(data[i] & 0x03) << 4];
            outBuf[j++] = '=';
        }
        outBuf[j++] = '=';
    }
    outBuf[j] = '\0';
    return j;
}

/* ================================================================
 * 内部辅助：Base64 解码
 * ================================================================ */
static int B64_DECODE_TABLE[256];
static BOOLEAN b64TableInit = FALSE;

static void InitB64DecodeTable(void)
{
    int i;
    if (b64TableInit) return;
    for (i = 0; i < 256; i++) B64_DECODE_TABLE[i] = -1;
    for (i = 0; i < 64; i++)  B64_DECODE_TABLE[(BYTE)B64_TABLE[i]] = i;
    B64_DECODE_TABLE['='] = 0;
    b64TableInit = TRUE;
}

static ULONG
Base64Decode(
    _In_  const char *str,
    _Out_ BYTE       *outBuf,
    _In_  ULONG       outBufLen
)
{
    ULONG strLen, i, j = 0;
    int   c0, c1, c2, c3;

    InitB64DecodeTable();
    strLen = (ULONG)strlen(str);

    for (i = 0; i + 3 < strLen; i += 4) {
        c0 = B64_DECODE_TABLE[(BYTE)str[i]];
        c1 = B64_DECODE_TABLE[(BYTE)str[i+1]];
        c2 = B64_DECODE_TABLE[(BYTE)str[i+2]];
        c3 = B64_DECODE_TABLE[(BYTE)str[i+3]];
        if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) break;
        if (j < outBufLen) outBuf[j++] = (BYTE)((c0 << 2) | (c1 >> 4));
        if (str[i+2] != '=' && j < outBufLen) outBuf[j++] = (BYTE)((c1 << 4) | (c2 >> 2));
        if (str[i+3] != '=' && j < outBufLen) outBuf[j++] = (BYTE)((c2 << 6) | c3);
    }
    return j;
}

/* ================================================================
 * 内部辅助：从 JSON 字符串中提取 Base64 字段值
 * ================================================================ */
static ULONG
JsonGetBase64Field(
    _In_  const char *json,
    _In_  const char *key,
    _Out_ BYTE       *outBuf,
    _In_  ULONG       outBufLen
)
{
    char    searchKey[128];
    const char *p;
    const char *start;
    const char *end;
    char    b64Str[4096];
    ULONG   b64Len;

    _snprintf_s(searchKey, sizeof(searchKey), _TRUNCATE, "\"%s\"", key);
    p = strstr(json, searchKey);
    if (!p) return 0;

    p += strlen(searchKey);
    while (*p == ' ' || *p == ':' || *p == ' ') p++;
    if (*p != '"') return 0;
    p++;

    start = p;
    end   = strchr(start, '"');
    if (!end) return 0;

    b64Len = (ULONG)(end - start);
    if (b64Len >= sizeof(b64Str)) return 0;

    RtlCopyMemory(b64Str, start, b64Len);
    b64Str[b64Len] = '\0';

    return Base64Decode(b64Str, outBuf, outBufLen);
}

/* ================================================================
 * 内部辅助：从 JSON 中提取字符串字段
 * ================================================================ */
static BOOLEAN
JsonGetStringField(
    _In_  const char *json,
    _In_  const char *key,
    _Out_ char       *outBuf,
    _In_  ULONG       outBufLen
)
{
    char    searchKey[128];
    const char *p;
    const char *start;
    const char *end;
    ULONG   len;

    _snprintf_s(searchKey, sizeof(searchKey), _TRUNCATE, "\"%s\"", key);
    p = strstr(json, searchKey);
    if (!p) return FALSE;

    p += strlen(searchKey);
    while (*p == ' ' || *p == ':' || *p == ' ') p++;
    if (*p != '"') return FALSE;
    p++;

    start = p;
    end   = strchr(start, '"');
    if (!end) return FALSE;

    len = (ULONG)(end - start);
    if (len >= outBufLen) len = outBufLen - 1;

    RtlCopyMemory(outBuf, start, len);
    outBuf[len] = '\0';
    return TRUE;
}

/* ================================================================
 * 处理 SELECT FIDO Applet
 *
 * 命令：00 A4 04 00 08 A0 00 00 06 47 2F 00 01
 * 响应：46 49 44 4F 5F 32 5F 30 90 00  ("FIDO_2_0" + SW_SUCCESS)
 * ================================================================ */
static NTSTATUS
HandleSelectApplet(
    _In_  PDEVICE_CONTEXT DevCtx,
    _In_  const BYTE     *apduData,
    _In_  ULONG           apduLen,
    _Out_ BYTE           *respBuf,
    _Out_ ULONG          *respLen
)
{
    /* FIDO_2_0 响应 */
    static const BYTE FIDO2_RESP[] = {
        'F', 'I', 'D', 'O', '_', '2', '_', '0',
        0x90, 0x00  /* SW_SUCCESS */
    };

    UNREFERENCED_PARAMETER(apduData);
    UNREFERENCED_PARAMETER(apduLen);

    if (*respLen < sizeof(FIDO2_RESP)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    DevCtx->AppletSelected = TRUE;
    RtlCopyMemory(respBuf, FIDO2_RESP, sizeof(FIDO2_RESP));
    *respLen = sizeof(FIDO2_RESP);

    return STATUS_SUCCESS;
}

/* ================================================================
 * 处理 CTAP2 命令（CLA=0x80, INS=0x10）
 *
 * 将 CBOR 数据 Base64 编码后通过 IPC 发送给 Go 后端，
 * 接收响应后解码并封装为 APDU 响应。
 * ================================================================ */
static NTSTATUS
HandleCtap2Command(
    _In_  PDEVICE_CONTEXT DevCtx,
    _In_  const BYTE     *ctapData,   /* [1字节命令码][CBOR参数] */
    _In_  ULONG           ctapLen,
    _Out_ BYTE           *respBuf,
    _Out_ ULONG          *respLen
)
{
    NTSTATUS    status;
    BYTE        ctapCmd;
    ULONG       cmdCode;
    char        reqJson[JSON_BUF_MAX];
    char        respJson[JSON_BUF_MAX];
    ULONG       ipcStatus = 0;
    char        b64In[IPC_BUF_MAX];
    BYTE        respCbor[APDU_RESP_MAX_LEN];
    ULONG       respCborLen;

    UNREFERENCED_PARAMETER(DevCtx);

    if (ctapLen < 1) {
        /* 返回 CTAP1_ERR_INVALID_LENGTH */
        if (*respLen >= 3) {
            respBuf[0] = 0x03;
            respBuf[1] = 0x67;
            respBuf[2] = 0x00;
            *respLen = 3;
        }
        return STATUS_SUCCESS;
    }

    ctapCmd = ctapData[0];

    /* 根据命令码选择 IPC 命令 */
    switch (ctapCmd) {
    case CTAP2_CMD_GET_INFO:
        cmdCode = CMD_FIDO_GET_INFO;
        break;
    case CTAP2_CMD_MAKE_CREDENTIAL:
        cmdCode = CMD_FIDO_MAKE_CREDENTIAL;
        break;
    case CTAP2_CMD_GET_ASSERTION:
        cmdCode = CMD_FIDO_GET_ASSERTION;
        break;
    case CTAP2_CMD_CLIENT_PIN:
        /* Q4:b 预留接口：PIN 管理暂不实现，返回 CTAP2_ERR_PIN_NOT_SET */
        if (*respLen >= 3) {
            respBuf[0] = 0x35; /* CTAP2_ERR_PIN_NOT_SET */
            respBuf[1] = 0x90;
            respBuf[2] = 0x00;
            *respLen = 3;
        }
        return STATUS_SUCCESS;
    case CTAP2_CMD_RESET:
        /* Q4:b 预留接口：Reset 暂不实现，返回 CTAP2_ERR_NOT_ALLOWED */
        if (*respLen >= 3) {
            respBuf[0] = 0x30; /* CTAP2_ERR_NOT_ALLOWED */
            respBuf[1] = 0x90;
            respBuf[2] = 0x00;
            *respLen = 3;
        }
        return STATUS_SUCCESS;
    default:
        /* 未知命令 */
        if (*respLen >= 3) {
            respBuf[0] = CTAP1_ERR_INVALID_COMMAND;
            respBuf[1] = 0x90;
            respBuf[2] = 0x00;
            *respLen = 3;
        }
        return STATUS_SUCCESS;
    }

    /* ---- 将 CBOR 数据 Base64 编码 ---- */
    if (ctapLen > 1) {
        Base64Encode(ctapData + 1, ctapLen - 1, b64In, sizeof(b64In));
    } else {
        b64In[0] = '\0';
    }

    /* ---- 构造请求 JSON ---- */
    _snprintf_s(reqJson, sizeof(reqJson), _TRUNCATE,
        "{\"cmd\":%u,\"cbor\":\"%s\"}",
        (unsigned)ctapCmd,
        b64In
    );

    /* ---- 调用 IPC ---- */
    status = IpcCall(cmdCode, reqJson, respJson, sizeof(respJson), &ipcStatus);

    if (!NT_SUCCESS(status)) {
        /* IPC 失败：返回 CTAP1_ERR_OTHER */
        if (*respLen >= 3) {
            respBuf[0] = CTAP1_ERR_OTHER;
            respBuf[1] = 0x90;
            respBuf[2] = 0x00;
            *respLen = 3;
        }
        return STATUS_SUCCESS; /* APDU 层面成功，CTAP 层面错误 */
    }

    if (ipcStatus != 0) {
        /* Go 后端返回错误 */
        if (*respLen >= 3) {
            respBuf[0] = (BYTE)(ipcStatus & 0xFF);
            respBuf[1] = 0x90;
            respBuf[2] = 0x00;
            *respLen = 3;
        }
        return STATUS_SUCCESS;
    }

    /* ---- 从响应 JSON 中提取 CBOR 数据 ---- */
    respCborLen = JsonGetBase64Field(respJson, "cbor", respCbor, sizeof(respCbor));

    /* ---- 构造 APDU 响应：[CTAP2_OK][CBOR数据][SW_SUCCESS] ---- */
    if (*respLen < 1 + respCborLen + 2) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    respBuf[0] = CTAP2_OK;
    if (respCborLen > 0) {
        RtlCopyMemory(respBuf + 1, respCbor, respCborLen);
    }
    respBuf[1 + respCborLen]     = 0x90;
    respBuf[1 + respCborLen + 1] = 0x00;
    *respLen = 1 + respCborLen + 2;

    return STATUS_SUCCESS;
}

/* ================================================================
 * CcidHandleApdu - APDU 处理入口
 *
 * 解析 ISO 7816 APDU 命令头，分发给对应处理函数。
 * ================================================================ */
NTSTATUS
CcidHandleApdu(
    _In_  PDEVICE_CONTEXT DevCtx,
    _In_  const BYTE     *SendBuf,
    _In_  ULONG           SendLen,
    _Out_ BYTE           *RecvBuf,
    _Out_ ULONG          *RecvLen
)
{
    BYTE    cla, ins, p1, p2;
    ULONG   lc = 0;
    const BYTE *data = NULL;

    /* APDU 最短 4 字节（CLA INS P1 P2） */
    if (SendLen < 4 || !SendBuf || !RecvBuf || !RecvLen || *RecvLen < 2) {
        if (RecvBuf && RecvLen && *RecvLen >= 2) {
            RecvBuf[0] = 0x6F;
            RecvBuf[1] = 0x00;
            *RecvLen = 2;
        }
        return STATUS_SUCCESS;
    }

    cla = SendBuf[0];
    ins = SendBuf[1];
    p1  = SendBuf[2];
    p2  = SendBuf[3];

    /* 解析 Lc 和数据字段 */
    if (SendLen > 4) {
        if (SendLen == 5) {
            /* Le only，无数据 */
            lc   = 0;
            data = NULL;
        } else if (SendBuf[4] != 0x00) {
            /* 短 APDU：Lc = SendBuf[4] */
            lc   = SendBuf[4];
            data = SendBuf + 5;
        } else if (SendLen >= 7) {
            /* 扩展 APDU：Lc = SendBuf[5..6] */
            lc   = ((ULONG)SendBuf[5] << 8) | SendBuf[6];
            data = SendBuf + 7;
        }
    }

    /* ---- SELECT 命令 ---- */
    if (cla == APDU_CLA_ISO && ins == APDU_INS_SELECT && p1 == 0x04 && p2 == 0x00) {
        /* 检查 AID */
        if (lc == FIDO_AID_LEN && data &&
            RtlCompareMemory(data, FIDO_AID, FIDO_AID_LEN) == FIDO_AID_LEN)
        {
            return HandleSelectApplet(DevCtx, data, lc, RecvBuf, RecvLen);
        }
        /* AID 不匹配 */
        RecvBuf[0] = 0x6A;
        RecvBuf[1] = 0x82; /* FILE_NOT_FOUND */
        *RecvLen = 2;
        return STATUS_SUCCESS;
    }

    /* ---- CTAP2 命令（CLA=0x80, INS=0x10） ---- */
    if (cla == APDU_CLA_FIDO && ins == APDU_INS_FIDO2) {
        if (!DevCtx->AppletSelected) {
            /* Applet 未选择 */
            RecvBuf[0] = 0x69;
            RecvBuf[1] = 0x85; /* CONDITIONS_NOT_SATISFIED */
            *RecvLen = 2;
            return STATUS_SUCCESS;
        }
        return HandleCtap2Command(DevCtx, data, lc, RecvBuf, RecvLen);
    }

    /* ---- 不支持的命令 ---- */
    RecvBuf[0] = 0x6D;
    RecvBuf[1] = 0x00; /* INS_NOT_SUPPORTED */
    *RecvLen = 2;
    return STATUS_SUCCESS;
}
