/*
 * opencert_fido.c - OpenCert FIDO2 CCID 虚拟智能卡实现
 *
 * 实现 FIDO2 CTAP2 over CCID 协议。
 * 通过 IPC Named Pipe 将 CTAP2 命令转发给 client-card Go 后端处理。
 * 私钥存储在 OpenCert 智能卡（本地/TPM/云端），Windows 仅作为传输层。
 *
 * 数据流：
 *   浏览器 WebAuthn
 *     → Windows webauthn.dll
 *     → Windows CCID 驱动（wudfrd.sys）
 *     → 本 DLL（SCardTransmit 回调）
 *     → IPC Named Pipe
 *     → client-card Go 后端
 *     → fido.Store（本地SQLite / TPM / 云端）
 */

#include "opencert_fido.h"
#include "ipc_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * 全局状态
 * ================================================================ */

/* 全局设备上下文（虚拟单卡，一个 CCID 设备） */
static FIDO_DEVICE_CTX g_ctx = { 0 };

/* ================================================================
 * DLL 入口
 * ================================================================ */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        /* 初始化设备上下文 */
        memset(&g_ctx, 0, sizeof(g_ctx));
        g_ctx.dwMagic   = FIDO_CTX_MAGIC;
        g_ctx.bSelected = FALSE;
        /* 建立 IPC 连接 */
        ipc_global_connect();
        break;

    case DLL_PROCESS_DETACH:
        /* 断开 IPC 连接 */
        ipc_global_disconnect();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

/* ================================================================
 * APDU 解析
 * ================================================================ */

/*
 * parse_apdu - 解析 APDU 命令字节流。
 * 支持短格式（Lc/Le ≤ 255）和扩展格式（Lc/Le ≤ 65535）。
 * 返回 0 成功，-1 格式错误。
 */
static int parse_apdu(const BYTE *buf, DWORD len, APDU_CMD *cmd)
{
    if (len < 4) return -1;

    cmd->bCLA   = buf[0];
    cmd->bINS   = buf[1];
    cmd->bP1    = buf[2];
    cmd->bP2    = buf[3];
    cmd->dwLc   = 0;
    cmd->pbData = NULL;
    cmd->dwLe   = 0;

    if (len == 4) {
        /* Case 1: CLA INS P1 P2 */
        return 0;
    }

    if (len == 5) {
        /* Case 2S: CLA INS P1 P2 Le */
        cmd->dwLe = buf[4] == 0 ? 256 : buf[4];
        return 0;
    }

    /* 检查是否为扩展 APDU（buf[4] == 0x00） */
    if (buf[4] == 0x00 && len >= 7) {
        /* 扩展格式 */
        DWORD lc = ((DWORD)buf[5] << 8) | buf[6];
        if (lc == 0) {
            /* Case 2E: CLA INS P1 P2 00 Le_H Le_L */
            cmd->dwLe = ((DWORD)buf[5] << 8) | buf[6];
            if (cmd->dwLe == 0) cmd->dwLe = 65536;
            return 0;
        }
        if (len < 7 + lc) return -1;
        cmd->dwLc   = lc;
        cmd->pbData = (BYTE *)(buf + 7);
        if (len == 7 + lc) {
            /* Case 3E */
            return 0;
        }
        if (len == 7 + lc + 2) {
            /* Case 4E */
            DWORD le = ((DWORD)buf[7 + lc] << 8) | buf[7 + lc + 1];
            cmd->dwLe = (le == 0) ? 65536 : le;
            return 0;
        }
        return -1;
    }

    /* 短格式 */
    DWORD lc = buf[4];
    if (lc == 0) {
        /* Case 2S: Le = buf[4] */
        cmd->dwLe = 256;
        return 0;
    }
    if (len < 5 + lc) return -1;
    cmd->dwLc   = lc;
    cmd->pbData = (BYTE *)(buf + 5);
    if (len == 5 + lc) {
        /* Case 3S */
        return 0;
    }
    if (len == 5 + lc + 1) {
        /* Case 4S */
        cmd->dwLe = buf[5 + lc] == 0 ? 256 : buf[5 + lc];
        return 0;
    }
    return -1;
}

/*
 * build_response - 构造 APDU 响应（数据 + 状态字）。
 * 返回写入的字节数。
 */
static DWORD build_response(BYTE *buf, DWORD buflen,
                             const BYTE *data, DWORD datalen,
                             WORD sw)
{
    DWORD total = datalen + 2;
    if (total > buflen) return 0;

    if (datalen > 0 && data != NULL) {
        memcpy(buf, data, datalen);
    }
    buf[datalen]     = (BYTE)(sw >> 8);
    buf[datalen + 1] = (BYTE)(sw & 0xFF);
    return total;
}

/* ================================================================
 * SELECT Applet 处理
 * ================================================================ */

static LONG fido_handle_select(FIDO_DEVICE_CTX *ctx,
                                const APDU_CMD  *cmd,
                                APDU_RESP       *resp)
{
    /* SELECT by AID: INS=A4, P1=04, P2=00 */
    if (cmd->bINS != APDU_INS_SELECT || cmd->bP1 != 0x04) {
        resp->wSW = APDU_SW_INS_NOT_SUPPORTED;
        return SCARD_S_SUCCESS;
    }

    /* 验证 AID */
    if (cmd->dwLc != FIDO_AID_LEN ||
        memcmp(cmd->pbData, FIDO_AID, FIDO_AID_LEN) != 0) {
        resp->wSW = APDU_SW_WRONG_DATA;
        return SCARD_S_SUCCESS;
    }

    ctx->bSelected = TRUE;

    /* 响应：FIDO_2_0 字符串 */
    static const BYTE fido_resp[] = { 'F','I','D','O','_','2','_','0' };
    resp->pbData = (BYTE *)malloc(sizeof(fido_resp));
    if (!resp->pbData) {
        resp->wSW = APDU_SW_UNKNOWN;
        return SCARD_S_SUCCESS;
    }
    memcpy(resp->pbData, fido_resp, sizeof(fido_resp));
    resp->dwLen = sizeof(fido_resp);
    resp->wSW   = APDU_SW_SUCCESS;
    return SCARD_S_SUCCESS;
}

/* ================================================================
 * CTAP2 命令分发
 * ================================================================ */

static LONG fido_handle_ctap2(FIDO_DEVICE_CTX *ctx,
                               const APDU_CMD  *cmd,
                               APDU_RESP       *resp)
{
    if (!ctx->bSelected) {
        resp->wSW = APDU_SW_CONDITIONS_NOT_SATISFIED;
        return SCARD_S_SUCCESS;
    }

    if (cmd->dwLc < 1 || cmd->pbData == NULL) {
        resp->wSW = APDU_SW_WRONG_LENGTH;
        return SCARD_S_SUCCESS;
    }

    BYTE ctap_cmd = cmd->pbData[0];
    const BYTE *cbor_req  = cmd->pbData + 1;
    DWORD       cbor_len  = cmd->dwLc - 1;

    LONG ret = SCARD_S_SUCCESS;
    switch (ctap_cmd) {
    case CTAP2_CMD_GET_INFO:
        ret = ctap2_get_info(ctx, cbor_req, cbor_len, resp);
        break;
    case CTAP2_CMD_MAKE_CREDENTIAL:
        ret = ctap2_make_credential(ctx, cbor_req, cbor_len, resp);
        break;
    case CTAP2_CMD_GET_ASSERTION:
        ret = ctap2_get_assertion(ctx, cbor_req, cbor_len, resp);
        break;
    default:
        /* 不支持的命令，返回 CTAP1_ERR_INVALID_COMMAND */
        resp->pbData = (BYTE *)malloc(1);
        if (resp->pbData) {
            resp->pbData[0] = CTAP1_ERR_INVALID_COMMAND;
            resp->dwLen     = 1;
        }
        resp->wSW = APDU_SW_SUCCESS;
        break;
    }
    return ret;
}

/* ================================================================
 * CTAP2 authenticatorGetInfo (0x04)
 * ================================================================ */

static LONG ctap2_get_info(FIDO_DEVICE_CTX *ctx,
                            const BYTE      *cbor_req,
                            DWORD            cbor_len,
                            APDU_RESP       *resp)
{
    (void)cbor_req;
    (void)cbor_len;

    /* 通过 IPC 获取认证器信息 */
    ipc_fd_t fd = ipc_global_fd();
    if (fd == IPC_INVALID_FD) {
        if (ipc_global_connect() != 0) {
            goto fallback;
        }
        fd = ipc_global_fd();
    }

    {
        char *resp_json = NULL;
        DWORD rv = 0;
        int ret = ipc_call(fd, CMD_FIDO_GET_INFO, "{}", &resp_json, &rv);
        if (ret == 0 && rv == 0 && resp_json != NULL) {
            /* 从响应中提取 cbor_info（base64 编码） */
            BYTE  *cbor_info = NULL;
            DWORD  cbor_info_len = 0;
            json_get_bytes_b64(resp_json, "cbor_info", &cbor_info, &cbor_info_len);
            free(resp_json);

            if (cbor_info != NULL && cbor_info_len > 0) {
                /* 响应：状态码(1) + CBOR 数据 */
                resp->pbData = (BYTE *)malloc(1 + cbor_info_len);
                if (resp->pbData) {
                    resp->pbData[0] = CTAP2_OK;
                    memcpy(resp->pbData + 1, cbor_info, cbor_info_len);
                    resp->dwLen = 1 + cbor_info_len;
                }
                free(cbor_info);
                resp->wSW = APDU_SW_SUCCESS;
                return SCARD_S_SUCCESS;
            }
            if (cbor_info) free(cbor_info);
        }
        if (resp_json) free(resp_json);
    }

fallback:
    /* IPC 失败时返回最小化的 GetInfo 响应（硬编码） */
    {
        /*
         * CBOR 编码的 authenticatorGetInfo 响应（最小化）：
         * {
         *   1: ["FIDO_2_0", "FIDO_2_1"],  -- versions
         *   3: h'AAGUID(16bytes)',          -- aaguid
         *   4: {"rk": true},               -- options
         * }
         */
        BYTE cbor_buf[128];
        DWORD pos = 0;

        /* Map with 3 entries */
        pos += cbor_encode_map_header(cbor_buf + pos, sizeof(cbor_buf) - pos, 3);
        /* key 1: versions */
        pos += cbor_encode_uint(cbor_buf + pos, sizeof(cbor_buf) - pos, 1);
        pos += cbor_encode_array_header(cbor_buf + pos, sizeof(cbor_buf) - pos, 2);
        pos += cbor_encode_text(cbor_buf + pos, sizeof(cbor_buf) - pos, "FIDO_2_0");
        pos += cbor_encode_text(cbor_buf + pos, sizeof(cbor_buf) - pos, "FIDO_2_1");
        /* key 3: aaguid */
        pos += cbor_encode_uint(cbor_buf + pos, sizeof(cbor_buf) - pos, 3);
        pos += cbor_encode_bytes(cbor_buf + pos, sizeof(cbor_buf) - pos,
                                  OPENCERT_AAGUID, OPENCERT_AAGUID_LEN);
        /* key 4: options {rk: true} */
        pos += cbor_encode_uint(cbor_buf + pos, sizeof(cbor_buf) - pos, 4);
        pos += cbor_encode_map_header(cbor_buf + pos, sizeof(cbor_buf) - pos, 1);
        pos += cbor_encode_text(cbor_buf + pos, sizeof(cbor_buf) - pos, "rk");
        pos += cbor_encode_bool(cbor_buf + pos, sizeof(cbor_buf) - pos, TRUE);

        resp->pbData = (BYTE *)malloc(1 + pos);
        if (resp->pbData) {
            resp->pbData[0] = CTAP2_OK;
            memcpy(resp->pbData + 1, cbor_buf, pos);
            resp->dwLen = 1 + pos;
        }
        resp->wSW = APDU_SW_SUCCESS;
    }
    return SCARD_S_SUCCESS;
}

/* ================================================================
 * CTAP2 authenticatorMakeCredential (0x01)
 * ================================================================ */

static LONG ctap2_make_credential(FIDO_DEVICE_CTX *ctx,
                                   const BYTE      *cbor_req,
                                   DWORD            cbor_len,
                                   APDU_RESP       *resp)
{
    (void)ctx;

    /* 将 CBOR 请求 base64 编码后通过 IPC 发送给 Go 后端 */
    char *cbor_b64 = base64_encode(cbor_req, cbor_len);
    if (!cbor_b64) {
        resp->pbData    = (BYTE *)malloc(1);
        if (resp->pbData) { resp->pbData[0] = CTAP1_ERR_OTHER; resp->dwLen = 1; }
        resp->wSW = APDU_SW_SUCCESS;
        return SCARD_S_SUCCESS;
    }

    /* 构造 JSON 请求 */
    char req_json[4096];
    _snprintf_s(req_json, sizeof(req_json), _TRUNCATE,
                "{\"cbor_req\":\"%s\"}", cbor_b64);
    free(cbor_b64);

    ipc_fd_t fd = ipc_global_fd();
    if (fd == IPC_INVALID_FD) ipc_global_connect();
    fd = ipc_global_fd();

    if (fd == IPC_INVALID_FD) {
        resp->pbData    = (BYTE *)malloc(1);
        if (resp->pbData) { resp->pbData[0] = CTAP1_ERR_OTHER; resp->dwLen = 1; }
        resp->wSW = APDU_SW_SUCCESS;
        return SCARD_S_SUCCESS;
    }

    char *resp_json = NULL;
    DWORD rv = 0;
    int ret = ipc_call(fd, CMD_FIDO_MAKE_CREDENTIAL, req_json, &resp_json, &rv);

    if (ret != 0 || rv != 0) {
        /* IPC 失败或后端返回错误 */
        BYTE ctap_err = (rv != 0) ? (BYTE)(rv & 0xFF) : CTAP1_ERR_OTHER;
        resp->pbData = (BYTE *)malloc(1);
        if (resp->pbData) { resp->pbData[0] = ctap_err; resp->dwLen = 1; }
        resp->wSW = APDU_SW_SUCCESS;
        if (resp_json) free(resp_json);
        return SCARD_S_SUCCESS;
    }

    /* 从响应中提取 cbor_resp（base64 编码的 attestationObject） */
    BYTE  *cbor_resp = NULL;
    DWORD  cbor_resp_len = 0;
    json_get_bytes_b64(resp_json, "cbor_resp", &cbor_resp, &cbor_resp_len);
    free(resp_json);

    if (cbor_resp == NULL || cbor_resp_len == 0) {
        resp->pbData = (BYTE *)malloc(1);
        if (resp->pbData) { resp->pbData[0] = CTAP1_ERR_OTHER; resp->dwLen = 1; }
        resp->wSW = APDU_SW_SUCCESS;
        if (cbor_resp) free(cbor_resp);
        return SCARD_S_SUCCESS;
    }

    /* 响应：状态码(1) + CBOR attestationObject */
    resp->pbData = (BYTE *)malloc(1 + cbor_resp_len);
    if (resp->pbData) {
        resp->pbData[0] = CTAP2_OK;
        memcpy(resp->pbData + 1, cbor_resp, cbor_resp_len);
        resp->dwLen = 1 + cbor_resp_len;
    }
    free(cbor_resp);
    resp->wSW = APDU_SW_SUCCESS;
    return SCARD_S_SUCCESS;
}

/* ================================================================
 * CTAP2 authenticatorGetAssertion (0x02)
 * ================================================================ */

static LONG ctap2_get_assertion(FIDO_DEVICE_CTX *ctx,
                                 const BYTE      *cbor_req,
                                 DWORD            cbor_len,
                                 APDU_RESP       *resp)
{
    (void)ctx;

    char *cbor_b64 = base64_encode(cbor_req, cbor_len);
    if (!cbor_b64) {
        resp->pbData = (BYTE *)malloc(1);
        if (resp->pbData) { resp->pbData[0] = CTAP1_ERR_OTHER; resp->dwLen = 1; }
        resp->wSW = APDU_SW_SUCCESS;
        return SCARD_S_SUCCESS;
    }

    char req_json[4096];
    _snprintf_s(req_json, sizeof(req_json), _TRUNCATE,
                "{\"cbor_req\":\"%s\"}", cbor_b64);
    free(cbor_b64);

    ipc_fd_t fd = ipc_global_fd();
    if (fd == IPC_INVALID_FD) ipc_global_connect();
    fd = ipc_global_fd();

    if (fd == IPC_INVALID_FD) {
        resp->pbData = (BYTE *)malloc(1);
        if (resp->pbData) { resp->pbData[0] = CTAP1_ERR_OTHER; resp->dwLen = 1; }
        resp->wSW = APDU_SW_SUCCESS;
        return SCARD_S_SUCCESS;
    }

    char *resp_json = NULL;
    DWORD rv = 0;
    int ret = ipc_call(fd, CMD_FIDO_GET_ASSERTION, req_json, &resp_json, &rv);

    if (ret != 0 || rv != 0) {
        BYTE ctap_err = (rv != 0) ? (BYTE)(rv & 0xFF) : CTAP1_ERR_OTHER;
        resp->pbData = (BYTE *)malloc(1);
        if (resp->pbData) { resp->pbData[0] = ctap_err; resp->dwLen = 1; }
        resp->wSW = APDU_SW_SUCCESS;
        if (resp_json) free(resp_json);
        return SCARD_S_SUCCESS;
    }

    BYTE  *cbor_resp = NULL;
    DWORD  cbor_resp_len = 0;
    json_get_bytes_b64(resp_json, "cbor_resp", &cbor_resp, &cbor_resp_len);
    free(resp_json);

    if (cbor_resp == NULL || cbor_resp_len == 0) {
        resp->pbData = (BYTE *)malloc(1);
        if (resp->pbData) { resp->pbData[0] = CTAP1_ERR_OTHER; resp->dwLen = 1; }
        resp->wSW = APDU_SW_SUCCESS;
        if (cbor_resp) free(cbor_resp);
        return SCARD_S_SUCCESS;
    }

    resp->pbData = (BYTE *)malloc(1 + cbor_resp_len);
    if (resp->pbData) {
        resp->pbData[0] = CTAP2_OK;
        memcpy(resp->pbData + 1, cbor_resp, cbor_resp_len);
        resp->dwLen = 1 + cbor_resp_len;
    }
    free(cbor_resp);
    resp->wSW = APDU_SW_SUCCESS;
    return SCARD_S_SUCCESS;
}

/* ================================================================
 * APDU 主处理入口
 * ================================================================ */

static LONG fido_handle_apdu(FIDO_DEVICE_CTX *ctx,
                              const APDU_CMD  *cmd,
                              APDU_RESP       *resp)
{
    /* 初始化响应 */
    resp->pbData = NULL;
    resp->dwLen  = 0;
    resp->wSW    = APDU_SW_UNKNOWN;

    /* SELECT Applet */
    if (cmd->bCLA == APDU_CLA_ISO && cmd->bINS == APDU_INS_SELECT) {
        return fido_handle_select(ctx, cmd, resp);
    }

    /* CTAP2 命令（CLA=0x80, INS=0x10） */
    if (cmd->bCLA == APDU_CLA_FIDO && cmd->bINS == APDU_INS_FIDO2) {
        return fido_handle_ctap2(ctx, cmd, resp);
    }

    /* 不支持的命令 */
    resp->wSW = APDU_SW_INS_NOT_SUPPORTED;
    return SCARD_S_SUCCESS;
}

/* ================================================================
 * SCardTransmit 回调（PC/SC 接口入口）
 * ================================================================ */

LONG WINAPI FidoTransmit(
    SCARDHANDLE           hCard,
    LPCSCARD_IO_REQUEST   pioSendPci,
    LPCBYTE               pbSendBuffer,
    DWORD                 cbSendLength,
    LPSCARD_IO_REQUEST    pioRecvPci,
    LPBYTE                pbRecvBuffer,
    LPDWORD               pcbRecvLength)
{
    (void)hCard;
    (void)pioSendPci;
    (void)pioRecvPci;

    if (!pbSendBuffer || cbSendLength < 4 ||
        !pbRecvBuffer || !pcbRecvLength || *pcbRecvLength < 2) {
        return SCARD_E_INVALID_PARAMETER;
    }

    /* 解析 APDU */
    APDU_CMD cmd = { 0 };
    if (parse_apdu(pbSendBuffer, cbSendLength, &cmd) != 0) {
        pbRecvBuffer[0] = (BYTE)(APDU_SW_WRONG_LENGTH >> 8);
        pbRecvBuffer[1] = (BYTE)(APDU_SW_WRONG_LENGTH & 0xFF);
        *pcbRecvLength  = 2;
        return SCARD_S_SUCCESS;
    }

    /* 处理 APDU */
    APDU_RESP resp = { 0 };
    LONG ret = fido_handle_apdu(&g_ctx, &cmd, &resp);

    if (ret != SCARD_S_SUCCESS) {
        if (resp.pbData) free(resp.pbData);
        return ret;
    }

    /* 构造响应 */
    DWORD written = build_response(pbRecvBuffer, *pcbRecvLength,
                                    resp.pbData, resp.dwLen, resp.wSW);
    if (resp.pbData) free(resp.pbData);

    if (written == 0) {
        return SCARD_E_INSUFFICIENT_BUFFER;
    }

    *pcbRecvLength = written;
    return SCARD_S_SUCCESS;
}

/* ================================================================
 * CBOR 编码辅助（最小化实现）
 * ================================================================ */

static DWORD cbor_encode_head(BYTE *buf, DWORD buflen, BYTE major, uint64_t val)
{
    if (buflen < 1) return 0;
    if (val <= 23) {
        buf[0] = (BYTE)(major | (BYTE)val);
        return 1;
    } else if (val <= 0xFF && buflen >= 2) {
        buf[0] = major | 0x18;
        buf[1] = (BYTE)val;
        return 2;
    } else if (val <= 0xFFFF && buflen >= 3) {
        buf[0] = major | 0x19;
        buf[1] = (BYTE)(val >> 8);
        buf[2] = (BYTE)(val & 0xFF);
        return 3;
    } else if (val <= 0xFFFFFFFF && buflen >= 5) {
        buf[0] = major | 0x1A;
        buf[1] = (BYTE)(val >> 24);
        buf[2] = (BYTE)(val >> 16);
        buf[3] = (BYTE)(val >> 8);
        buf[4] = (BYTE)(val & 0xFF);
        return 5;
    }
    return 0;
}

static DWORD cbor_encode_uint(BYTE *buf, DWORD buflen, uint64_t val)
{
    return cbor_encode_head(buf, buflen, (BYTE)(CBOR_UINT << 5), val);
}

static DWORD cbor_encode_bytes(BYTE *buf, DWORD buflen, const BYTE *data, DWORD datalen)
{
    DWORD hlen = cbor_encode_head(buf, buflen, (BYTE)(CBOR_BYTES << 5), datalen);
    if (hlen == 0 || hlen + datalen > buflen) return 0;
    memcpy(buf + hlen, data, datalen);
    return hlen + datalen;
}

static DWORD cbor_encode_text(BYTE *buf, DWORD buflen, const char *str)
{
    DWORD slen = (DWORD)strlen(str);
    DWORD hlen = cbor_encode_head(buf, buflen, (BYTE)(CBOR_TEXT << 5), slen);
    if (hlen == 0 || hlen + slen > buflen) return 0;
    memcpy(buf + hlen, str, slen);
    return hlen + slen;
}

static DWORD cbor_encode_map_header(BYTE *buf, DWORD buflen, DWORD count)
{
    return cbor_encode_head(buf, buflen, (BYTE)(CBOR_MAP << 5), count);
}

static DWORD cbor_encode_array_header(BYTE *buf, DWORD buflen, DWORD count)
{
    return cbor_encode_head(buf, buflen, (BYTE)(CBOR_ARRAY << 5), count);
}

static DWORD cbor_encode_bool(BYTE *buf, DWORD buflen, BOOL val)
{
    if (buflen < 1) return 0;
    buf[0] = val ? CBOR_TRUE : CBOR_FALSE;
    return 1;
}

/* ================================================================
 * Base64 编解码
 * ================================================================ */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const BYTE *data, DWORD len)
{
    DWORD out_len = ((len + 2) / 3) * 4 + 1;
    char *out = (char *)malloc(out_len);
    if (!out) return NULL;

    DWORD i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        out[j++] = b64_table[(data[i] >> 2) & 0x3F];
        out[j++] = b64_table[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)];
        out[j++] = b64_table[((data[i+1] & 0x0F) << 2) | ((data[i+2] >> 6) & 0x03)];
        out[j++] = b64_table[data[i+2] & 0x3F];
    }
    if (i < len) {
        out[j++] = b64_table[(data[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            out[j++] = b64_table[((data[i] & 0x03) << 4) | ((data[i+1] >> 4) & 0x0F)];
            out[j++] = b64_table[(data[i+1] & 0x0F) << 2];
        } else {
            out[j++] = b64_table[(data[i] & 0x03) << 4];
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

static BYTE *base64_decode(const char *str, DWORD *out_len)
{
    DWORD slen = (DWORD)strlen(str);
    DWORD buf_len = (slen / 4) * 3 + 4;
    BYTE *out = (BYTE *)malloc(buf_len);
    if (!out) return NULL;

    DWORD i, j = 0;
    for (i = 0; i + 3 < slen; i += 4) {
        int v0 = b64_char_val(str[i]);
        int v1 = b64_char_val(str[i+1]);
        int v2 = b64_char_val(str[i+2]);
        int v3 = b64_char_val(str[i+3]);
        if (v0 < 0 || v1 < 0) break;
        out[j++] = (BYTE)((v0 << 2) | (v1 >> 4));
        if (str[i+2] != '=' && v2 >= 0) {
            out[j++] = (BYTE)((v1 << 4) | (v2 >> 2));
            if (str[i+3] != '=' && v3 >= 0) {
                out[j++] = (BYTE)((v2 << 6) | v3);
            }
        }
    }
    *out_len = j;
    return out;
}

/* ================================================================
 * JSON 轻量级解析辅助
 * ================================================================ */

/*
 * json_get_string - 从 JSON 字符串中提取指定 key 的字符串值。
 * 仅支持简单的 {"key":"value"} 格式，不支持嵌套。
 */
static const char *json_get_string(const char *json, const char *key,
                                    char *out, DWORD outlen)
{
    if (!json || !key || !out || outlen == 0) return NULL;

    /* 构造搜索模式："key": */
    char pattern[128];
    _snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "\"%s\":", key);

    const char *pos = strstr(json, pattern);
    if (!pos) return NULL;

    pos += strlen(pattern);
    /* 跳过空白 */
    while (*pos == ' ' || *pos == '\t') pos++;
    if (*pos != '"') return NULL;
    pos++; /* 跳过开头引号 */

    DWORD i = 0;
    while (*pos && *pos != '"' && i < outlen - 1) {
        if (*pos == '\\') pos++; /* 跳过转义字符 */
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return out;
}

/*
 * json_get_bytes_b64 - 从 JSON 中提取 base64 编码的字节数组。
 * 调用方负责 free(*out)。
 */
static const char *json_get_bytes_b64(const char *json, const char *key,
                                       BYTE **out, DWORD *outlen)
{
    char b64_str[65536];
    if (!json_get_string(json, key, b64_str, sizeof(b64_str))) {
        *out    = NULL;
        *outlen = 0;
        return NULL;
    }
    *out = base64_decode(b64_str, outlen);
    return (const char *)*out;
}
