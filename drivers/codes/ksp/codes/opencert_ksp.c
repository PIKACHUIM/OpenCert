/*
 * opencert_ksp.c - OpenCert Key Storage Provider (KSP) Implementation
 *
 * This KSP DLL implements the Windows CNG NCrypt provider interface.
 * It forwards all cryptographic operations (sign/decrypt) to the
 * client-card backend via Named Pipe IPC.
 *
 * Architecture:
 *   Windows App (Edge/Outlook) -> NCryptSignHash()
 *       -> This KSP DLL -> Named Pipe IPC -> client-card backend
 *       -> Returns signature
 */

#include "opencert_ksp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wincred.h>

/* ---- Debug Logging ---- */
static const char *ksp_get_log_path(void)
{
    static char path[MAX_PATH] = {0};
    if (path[0] == '\0') {
        /* 优先使用 TEMP 环境变量（用户可写），回退到 C:\Windows\Temp */
        DWORD len = GetEnvironmentVariableA("TEMP", path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            len = GetEnvironmentVariableA("TMP", path, MAX_PATH);
        }
        if (len == 0 || len >= MAX_PATH) {
            strcpy(path, "C:\\Windows\\Temp");
        }
        strcat(path, "\\ksp_debug.log");
    }
    return path;
}

static void ksp_log(const char *fmt, ...)
{
    FILE *f = fopen(ksp_get_log_path(), "a");
    if (f) {
        /* 写入时间戳 */
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
}

/* ---- Base64 Encode/Decode (minimal implementation) ---- */

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const BYTE *data, DWORD len)
{
    DWORD out_len = ((len + 2) / 3) * 4;
    char *out = (char *)malloc(out_len + 1);
    if (!out) return NULL;

    DWORD i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        DWORD val = (data[i] << 16) |
                    ((i + 1 < len ? data[i + 1] : 0) << 8) |
                    (i + 2 < len ? data[i + 2] : 0);
        out[j]     = b64_table[(val >> 18) & 0x3F];
        out[j + 1] = b64_table[(val >> 12) & 0x3F];
        out[j + 2] = (i + 1 < len) ? b64_table[(val >> 6) & 0x3F] : '=';
        out[j + 3] = (i + 2 < len) ? b64_table[val & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

static int b64_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static BYTE *b64_decode(const char *s, DWORD *out_len)
{
    DWORD slen = (DWORD)strlen(s);
    if (slen % 4 != 0) return NULL;

    DWORD decoded_len = (slen / 4) * 3;
    if (slen > 0 && s[slen - 1] == '=') decoded_len--;
    if (slen > 1 && s[slen - 2] == '=') decoded_len--;

    BYTE *out = (BYTE *)malloc(decoded_len);
    if (!out) return NULL;

    DWORD i, j;
    for (i = 0, j = 0; i < slen; i += 4) {
        int a = b64_decode_char(s[i]);
        int b = b64_decode_char(s[i + 1]);
        int c = (s[i + 2] != '=') ? b64_decode_char(s[i + 2]) : 0;
        int d = (s[i + 3] != '=') ? b64_decode_char(s[i + 3]) : 0;

        if (a < 0 || b < 0) { free(out); return NULL; }

        DWORD val = (a << 18) | (b << 12) | (c << 6) | d;
        if (j < decoded_len) out[j++] = (BYTE)((val >> 16) & 0xFF);
        if (j < decoded_len) out[j++] = (BYTE)((val >> 8) & 0xFF);
        if (j < decoded_len) out[j++] = (BYTE)(val & 0xFF);
    }

    *out_len = decoded_len;
    return out;
}

/* ---- IPC Communication ---- */

static DWORD u32_to_be(DWORD v) { return _byteswap_ulong(v); }
static DWORD be_to_u32(DWORD v) { return _byteswap_ulong(v); }

static int raw_write(HANDLE h, const void *buf, DWORD len)
{
    const char *p = (const char *)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        DWORD written = 0;
        if (!WriteFile(h, p, remaining, &written, NULL))
            return -1;
        p += written;
        remaining -= written;
    }
    return 0;
}

static int raw_read(HANDLE h, void *buf, DWORD len)
{
    char *p = (char *)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        DWORD read_bytes = 0;
        if (!ReadFile(h, p, remaining, &read_bytes, NULL) || read_bytes == 0)
            return -1;
        p += read_bytes;
        remaining -= read_bytes;
    }
    return 0;
}

HANDLE ksp_ipc_connect(void)
{
    HANDLE h;
    int retries = 3;

    ksp_log("ksp_ipc_connect: attempting to connect to %s", IPC_PIPE_NAME);

    while (retries-- > 0) {
        h = CreateFileA(
            IPC_PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL
        );
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(h, &mode, NULL, NULL);
            ksp_log("ksp_ipc_connect: SUCCESS, handle=%p", h);
            return h;
        }
        DWORD err = GetLastError();
        ksp_log("ksp_ipc_connect: CreateFile failed, error=%u (retries left=%d)", err, retries);
        Sleep(500);
    }
    ksp_log("ksp_ipc_connect: FAILED after all retries");
    return INVALID_HANDLE_VALUE;
}

void ksp_ipc_disconnect(HANDLE hPipe)
{
    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);
}

int ksp_ipc_call(HANDLE hPipe, DWORD cmd,
                 const char *req_json,
                 char **resp_json, DWORD *out_rv)
{
    DWORD req_len = req_json ? (DWORD)strlen(req_json) : 0;

    ksp_log("ksp_ipc_call: cmd=0x%04X, req_len=%u, pipe=%p", cmd, req_len, hPipe);

    /* Send frame: Magic + Cmd + Len + Payload */
    BYTE header[IPC_HEADER_SIZE];
    DWORD magic_be = u32_to_be(IPC_MAGIC);
    DWORD cmd_be = u32_to_be(cmd);
    DWORD len_be = u32_to_be(req_len);
    memcpy(header + 0, &magic_be, 4);
    memcpy(header + 4, &cmd_be, 4);
    memcpy(header + 8, &len_be, 4);

    if (raw_write(hPipe, header, IPC_HEADER_SIZE) != 0) {
        ksp_log("ksp_ipc_call: raw_write header FAILED, error=%u", GetLastError());
        return -1;
    }
    if (req_len > 0 && raw_write(hPipe, req_json, req_len) != 0) {
        ksp_log("ksp_ipc_call: raw_write payload FAILED, error=%u", GetLastError());
        return -1;
    }

    ksp_log("ksp_ipc_call: request sent, waiting for response...");

    /* Receive response */
    BYTE resp_header[IPC_HEADER_SIZE];
    if (raw_read(hPipe, resp_header, IPC_HEADER_SIZE) != 0) {
        ksp_log("ksp_ipc_call: raw_read resp_header FAILED, error=%u", GetLastError());
        return -1;
    }

    DWORD resp_magic, resp_cmd, resp_len;
    memcpy(&resp_magic, resp_header + 0, 4); resp_magic = be_to_u32(resp_magic);
    memcpy(&resp_cmd, resp_header + 4, 4);   resp_cmd = be_to_u32(resp_cmd);
    memcpy(&resp_len, resp_header + 8, 4);   resp_len = be_to_u32(resp_len);

    ksp_log("ksp_ipc_call: resp_magic=0x%08X, resp_cmd=0x%04X, resp_len=%u",
            resp_magic, resp_cmd, resp_len);

    if (resp_magic != IPC_MAGIC || resp_len > IPC_MAX_PAYLOAD) {
        ksp_log("ksp_ipc_call: invalid response (magic mismatch or len too large)");
        return -1;
    }

    *out_rv = 0x00000005; /* CKR_GENERAL_ERROR default */
    if (resp_json) *resp_json = NULL;

    if (resp_len > 0) {
        char *buf = (char *)malloc(resp_len + 1);
        if (!buf) return -1;
        if (raw_read(hPipe, buf, resp_len) != 0) {
            ksp_log("ksp_ipc_call: raw_read payload FAILED, error=%u", GetLastError());
            free(buf);
            return -1;
        }
        buf[resp_len] = '\0';

        ksp_log("ksp_ipc_call: response payload: %.200s", buf);

        /* Parse "rv" field */
        const char *rv_pos = strstr(buf, "\"rv\":");
        if (rv_pos) *out_rv = (DWORD)strtoul(rv_pos + 5, NULL, 10);

        if (resp_json) {
            *resp_json = buf;
        } else {
            free(buf);
        }
    }

    ksp_log("ksp_ipc_call: done, rv=%u", *out_rv);
    return 0;
}

/* ---- JSON Helper: extract base64 field ---- */

static BYTE *json_get_b64_field(const char *json, const char *key, DWORD *out_len)
{
    char search[128];
    _snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *pos = strstr(json, search);
    if (!pos) return NULL;

    pos += strlen(search);
    const char *end = strchr(pos, '"');
    if (!end) return NULL;

    DWORD b64_len = (DWORD)(end - pos);
    char *b64_str = (char *)malloc(b64_len + 1);
    if (!b64_str) return NULL;
    memcpy(b64_str, pos, b64_len);
    b64_str[b64_len] = '\0';

    BYTE *decoded = b64_decode(b64_str, out_len);
    free(b64_str);
    return decoded;
}

/* ---- ASN.1 / Public Key Conversion ---- */

static int asn1_read_len(const BYTE *p, DWORD remaining, DWORD *out_len, DWORD *out_consumed)
{
    if (remaining < 1) return -1;
    if (p[0] < 0x80) { *out_len = p[0]; *out_consumed = 1; return 0; }
    DWORD nbytes = p[0] & 0x7F;
    if (nbytes == 0 || nbytes > 4 || remaining < 1 + nbytes) return -1;
    DWORD len = 0;
    for (DWORD i = 0; i < nbytes; i++) len = (len << 8) | p[1 + i];
    *out_len = len; *out_consumed = 1 + nbytes; return 0;
}

static int spki_extract_rsa(const BYTE *spki, DWORD spki_len,
    const BYTE **out_mod, DWORD *out_mod_len, const BYTE **out_exp, DWORD *out_exp_len)
{
    if (spki_len < 4 || spki[0] != 0x30) return -1;
    DWORD len, consumed;
    if (asn1_read_len(spki + 1, spki_len - 1, &len, &consumed) != 0) return -1;
    const BYTE *p = spki + 1 + consumed; DWORD remaining = len;
    /* Skip AlgorithmIdentifier SEQUENCE */
    if (remaining < 2 || p[0] != 0x30) return -1;
    if (asn1_read_len(p + 1, remaining - 1, &len, &consumed) != 0) return -1;
    DWORD alg_total = 1 + consumed + len;
    if (alg_total > remaining) return -1;
    p += alg_total; remaining -= alg_total;
    /* BIT STRING */
    if (remaining < 2 || p[0] != 0x03) return -1;
    if (asn1_read_len(p + 1, remaining - 1, &len, &consumed) != 0) return -1;
    p += 1 + consumed;
    if (len < 1) return -1;
    p += 1; /* skip unused-bits byte */
    DWORD bs_len = len - 1;
    /* RSAPublicKey SEQUENCE */
    if (bs_len < 2 || p[0] != 0x30) return -1;
    if (asn1_read_len(p + 1, bs_len - 1, &len, &consumed) != 0) return -1;
    p += 1 + consumed;
    /* modulus INTEGER */
    if (p[0] != 0x02) return -1;
    if (asn1_read_len(p + 1, len, &len, &consumed) != 0) return -1;
    const BYTE *mod = p + 1 + consumed; DWORD mod_len = len;
    if (mod_len > 0 && mod[0] == 0x00) { mod++; mod_len--; }
    p = p + 1 + consumed + len;
    /* publicExponent INTEGER */
    if (p[0] != 0x02) return -1;
    if (asn1_read_len(p + 1, 16, &len, &consumed) != 0) return -1;
    const BYTE *exp = p + 1 + consumed; DWORD exp_len = len;
    if (exp_len > 0 && exp[0] == 0x00) { exp++; exp_len--; }
    *out_mod = mod; *out_mod_len = mod_len;
    *out_exp = exp; *out_exp_len = exp_len;
    return 0;
}

static BYTE *spki_to_rsapublic_blob(const BYTE *spki, DWORD spki_len, DWORD *out_blob_len)
{
    const BYTE *modulus, *exp; DWORD mod_len, exp_len;
    if (spki_extract_rsa(spki, spki_len, &modulus, &mod_len, &exp, &exp_len) != 0) return NULL;
    DWORD blob_len = sizeof(BCRYPT_RSAKEY_BLOB) + exp_len + mod_len;
    BYTE *blob = (BYTE *)malloc(blob_len);
    if (!blob) return NULL;
    BCRYPT_RSAKEY_BLOB *hdr = (BCRYPT_RSAKEY_BLOB *)blob;
    hdr->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    hdr->BitLength = mod_len * 8;
    hdr->cbPublicExp = exp_len;
    hdr->cbModulus = mod_len;
    hdr->cbPrime1 = 0; hdr->cbPrime2 = 0;
    BYTE *dst = blob + sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(dst, exp, exp_len); dst += exp_len;
    memcpy(dst, modulus, mod_len);
    *out_blob_len = blob_len;
    return blob;
}

/* ---- NCrypt Provider Functions ---- */

static SECURITY_STATUS WINAPI KspOpenProvider(
    NCRYPT_PROV_HANDLE *phProvider,
    LPCWSTR pszProviderName,
    DWORD dwFlags)
{
    ksp_log("KspOpenProvider: name=%ls, flags=0x%X", pszProviderName, dwFlags);

    OPENCERT_KSP_PROVIDER *prov = (OPENCERT_KSP_PROVIDER *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OPENCERT_KSP_PROVIDER));
    if (!prov) return NTE_NO_MEMORY;

    prov->cbLength = sizeof(OPENCERT_KSP_PROVIDER);
    prov->dwMagic = KSP_PROVIDER_MAGIC;
    prov->dwFlags = dwFlags;
    prov->hPipe = INVALID_HANDLE_VALUE;

    *phProvider = (NCRYPT_PROV_HANDLE)prov;
    ksp_log("KspOpenProvider: SUCCESS, handle=%p", prov);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI KspFreeProvider(NCRYPT_PROV_HANDLE hProvider)
{
    OPENCERT_KSP_PROVIDER *prov = (OPENCERT_KSP_PROVIDER *)hProvider;
    if (!prov || prov->dwMagic != KSP_PROVIDER_MAGIC)
        return NTE_INVALID_HANDLE;

    if (prov->hPipe != INVALID_HANDLE_VALUE)
        ksp_ipc_disconnect(prov->hPipe);

    prov->dwMagic = 0;
    HeapFree(GetProcessHeap(), 0, prov);
    return ERROR_SUCCESS;
}

/* Ensure IPC connection is established */
static HANDLE ksp_ensure_pipe(OPENCERT_KSP_PROVIDER *prov)
{
    if (prov->hPipe == INVALID_HANDLE_VALUE)
        prov->hPipe = ksp_ipc_connect();
    return prov->hPipe;
}

/* ---- PIN Prompt and Login ---- */

/*
 * ksp_prompt_pin - 弹出 Windows PIN 输入对话框。
 * 使用 CredUIPromptForCredentialsW 显示标准的 Windows 凭据输入框。
 * card_name: 智能卡名称（显示在弹窗中）
 * card_uuid: 智能卡 UUID（显示在弹窗中）
 * 返回 0 表示成功（PIN 写入 pin_buf），非 0 表示用户取消或失败。
 */
static int ksp_prompt_pin(const WCHAR *card_name, const WCHAR *card_uuid,
                          char *pin_buf, DWORD pin_buf_size, HWND hWndParent)
{
    /* 构建弹窗消息文本：显示卡片名称和 UUID */
    WCHAR message[512];
    _snwprintf(message, 512,
        L"请认证智能卡 %ls 以继续操作",
        card_name ? card_name : L"OpenCert SmartCard"
        );

    CREDUI_INFOW cui = {0};
    cui.cbSize = sizeof(cui);
    cui.hwndParent = hWndParent;
    cui.pszMessageText = message;
    cui.pszCaptionText = L"OpenCert 智能卡认证";

    WCHAR username[256] = {0};
    if (card_uuid) {
        wcscpy_s(username, 256, card_uuid);
    } else {
        wcscpy_s(username, 256, L"Unknown SmartCard");
    }
    WCHAR password[256] = {0};
    BOOL save = FALSE;

    ksp_log("ksp_prompt_pin: showing PIN dialog for card=%ls, uuid=%ls",
            card_name ? card_name : L"(null)",
            card_uuid ? card_uuid : L"(null)");

    DWORD result = CredUIPromptForCredentialsW(
        &cui,
        L"OpenCert",       /* target name */
        NULL,              /* reserved */
        0,                 /* auth error (0 = first attempt) */
        username, 256,
        password, 256,
        &save,
        CREDUI_FLAGS_GENERIC_CREDENTIALS |
        CREDUI_FLAGS_DO_NOT_PERSIST |
        CREDUI_FLAGS_EXCLUDE_CERTIFICATES |
        CREDUI_FLAGS_KEEP_USERNAME |
        CREDUI_FLAGS_ALWAYS_SHOW_UI
    );

    if (result != ERROR_SUCCESS) {
        ksp_log("ksp_prompt_pin: user cancelled or error, result=%u", result);
        SecureZeroMemory(password, sizeof(password));
        return -1;
    }

    /* 将 WCHAR PIN 转换为 UTF-8 */
    int len = WideCharToMultiByte(CP_UTF8, 0, password, -1,
                                  pin_buf, pin_buf_size, NULL, NULL);
    SecureZeroMemory(password, sizeof(password));

    if (len <= 0) {
        ksp_log("ksp_prompt_pin: WideCharToMultiByte failed");
        return -1;
    }

    ksp_log("ksp_prompt_pin: PIN obtained (len=%d)", len - 1);
    return 0;
}

/*
 * ksp_login - 发送 CmdKSPLogin 命令给后端，执行 PIN 登录。
 * card_uuid_utf8: 卡片 UUID（从容器名中提取）
 * pin_utf8: 用户输入的 PIN（UTF-8）
 * 返回 0 表示登录成功，非 0 表示失败。
 */
static int ksp_login(HANDLE hPipe, const char *card_uuid_utf8, const char *pin_utf8)
{
    char req[1024];
    _snprintf(req, sizeof(req), "{\"card_uuid\":\"%s\",\"pin\":\"%s\"}",
              card_uuid_utf8, pin_utf8);

    char *resp = NULL;
    DWORD rv = 0;
    int ret = ksp_ipc_call(hPipe, CMD_KSP_LOGIN, req, &resp, &rv);

    /* 安全清除请求中的 PIN */
    SecureZeroMemory(req, sizeof(req));

    if (resp) free(resp);

    if (ret != 0) {
        ksp_log("ksp_login: IPC call failed");
        return -1;
    }

    if (rv == CKR_OK) {
        ksp_log("ksp_login: SUCCESS");
        return 0;
    }

    ksp_log("ksp_login: FAILED, rv=%u", rv);
    return (int)rv;
}

/*
 * ksp_extract_card_uuid - 从容器名中提取 card_uuid。
 * 容器名格式：OpenCert_<card_uuid>_<cert_uuid>
 * 由于 card_uuid 本身包含连字符，使用最后一个 '_' 分隔。
 */
static int ksp_extract_card_uuid(const char *container_utf8, char *card_uuid, DWORD buf_size)
{
    const char *prefix = "OpenCert_";
    if (strncmp(container_utf8, prefix, strlen(prefix)) != 0)
        return -1;

    const char *after_prefix = container_utf8 + strlen(prefix);
    const char *last_underscore = strrchr(after_prefix, '_');
    if (!last_underscore || last_underscore == after_prefix)
        return -1;

    DWORD uuid_len = (DWORD)(last_underscore - after_prefix);
    if (uuid_len >= buf_size)
        return -1;

    memcpy(card_uuid, after_prefix, uuid_len);
    card_uuid[uuid_len] = '\0';
    return 0;
}

/*
 * ksp_handle_login_required - 处理 CKR_USER_NOT_LOGGED_IN 错误。
 * 弹出 PIN 输入框，发送 Login 命令，成功后返回 0（调用者应重试原始操作）。
 * card_name_utf8: 卡片名称（从 IPC 响应中解析，可为 NULL）
 * card_uuid_hint: 卡片 UUID（从 IPC 响应中解析，可为 NULL，会回退到从容器名提取）
 */
static int ksp_handle_login_required(OPENCERT_KSP_PROVIDER *prov, const WCHAR *container_name,
                                     const char *card_name_utf8, const char *card_uuid_hint,
                                     HWND hWndParent)
{
    /* 提取 card_uuid（优先使用 hint，否则从容器名提取） */
    char container_utf8[512];
    WideCharToMultiByte(CP_UTF8, 0, container_name, -1,
                       container_utf8, sizeof(container_utf8), NULL, NULL);

    char card_uuid[256];
    if (card_uuid_hint && card_uuid_hint[0] != '\0') {
        strncpy(card_uuid, card_uuid_hint, sizeof(card_uuid) - 1);
        card_uuid[sizeof(card_uuid) - 1] = '\0';
    } else if (ksp_extract_card_uuid(container_utf8, card_uuid, sizeof(card_uuid)) != 0) {
        ksp_log("ksp_handle_login_required: failed to extract card_uuid");
        return -1;
    }

    /* 将卡片名称和 UUID 转换为 WCHAR 用于弹窗显示 */
    WCHAR card_name_w[256] = {0};
    WCHAR card_uuid_w[256] = {0};

    if (card_name_utf8 && card_name_utf8[0] != '\0') {
        MultiByteToWideChar(CP_UTF8, 0, card_name_utf8, -1, card_name_w, 256);
    } else {
        wcscpy_s(card_name_w, 256, L"OpenCert SmartCard");
    }
    MultiByteToWideChar(CP_UTF8, 0, card_uuid, -1, card_uuid_w, 256);

    /* 弹出 PIN 输入框（显示卡片名称和 UUID） */
    char pin[256] = {0};
    if (ksp_prompt_pin(card_name_w, card_uuid_w, pin, sizeof(pin), hWndParent) != 0) {
        ksp_log("ksp_handle_login_required: user cancelled PIN input");
        return -1;  /* 用户取消 */
    }

    /* 确保 pipe 连接 */
    HANDLE hPipe = ksp_ensure_pipe(prov);
    if (hPipe == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(pin, sizeof(pin));
        return -1;
    }

    /* 发送 Login 命令 */
    int ret = ksp_login(hPipe, card_uuid, pin);
    SecureZeroMemory(pin, sizeof(pin));

    return ret;
}

static SECURITY_STATUS WINAPI KspOpenKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE *phKey,
    LPCWSTR pszKeyName,
    DWORD dwLegacyKeySpec,
    DWORD dwFlags)
{
    OPENCERT_KSP_PROVIDER *prov = (OPENCERT_KSP_PROVIDER *)hProvider;
    if (!prov || prov->dwMagic != KSP_PROVIDER_MAGIC)
        return NTE_INVALID_HANDLE;
    if (!pszKeyName || !phKey)
        return NTE_INVALID_PARAMETER;

    ksp_log("KspOpenKey: container=%ls, legacyKeySpec=%u, flags=0x%X",
            pszKeyName, dwLegacyKeySpec, dwFlags);

    OPENCERT_KSP_KEY *key = (OPENCERT_KSP_KEY *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OPENCERT_KSP_KEY));
    if (!key) return NTE_NO_MEMORY;

    key->cbLength = sizeof(OPENCERT_KSP_KEY);
    key->dwMagic = KSP_KEY_MAGIC;
    key->dwFlags = dwFlags;
    key->pProvider = prov;
    wcsncpy_s(key->szContainer, 256, pszKeyName, _TRUNCATE);

    /* Query key info from backend */
    HANDLE hPipe = ksp_ensure_pipe(prov);
    if (hPipe != INVALID_HANDLE_VALUE) {
        /* Convert container name to UTF-8 for JSON */
        char container_utf8[512];
        WideCharToMultiByte(CP_UTF8, 0, pszKeyName, -1,
                           container_utf8, sizeof(container_utf8), NULL, NULL);

        char req[1024];
        _snprintf(req, sizeof(req), "{\"container\":\"%s\"}", container_utf8);

        char *resp = NULL;
        DWORD rv = 0;
        int ipc_ret = ksp_ipc_call(hPipe, CMD_KSP_GET_KEY_INFO, req, &resp, &rv);

        /* 如果后端返回 CKR_USER_NOT_LOGGED_IN，弹出 PIN 输入框 */
        if (ipc_ret == 0 && rv == CKR_USER_NOT_LOGGED_IN) {
            /* 从响应中解析卡片名称和 UUID */
            char card_name_utf8[256] = {0};
            char card_uuid_utf8[256] = {0};
            if (resp) {
                const char *name_pos = strstr(resp, "\"card_name\":\"");
                if (name_pos) {
                    name_pos += 13;
                    const char *name_end = strchr(name_pos, '"');
                    if (name_end && (name_end - name_pos) < 256) {
                        memcpy(card_name_utf8, name_pos, name_end - name_pos);
                    }
                }
                const char *uuid_pos = strstr(resp, "\"card_uuid\":\"");
                if (uuid_pos) {
                    uuid_pos += 13;
                    const char *uuid_end = strchr(uuid_pos, '"');
                    if (uuid_end && (uuid_end - uuid_pos) < 256) {
                        memcpy(card_uuid_utf8, uuid_pos, uuid_end - uuid_pos);
                    }
                }
                free(resp); resp = NULL;
            }
            ksp_log("KspOpenKey: Slot not logged in, prompting for PIN (card=%s, uuid=%s)",
                    card_name_utf8, card_uuid_utf8);

            if (ksp_handle_login_required(prov, pszKeyName, card_name_utf8, card_uuid_utf8, NULL) == 0) {
                /* Login 成功，重新连接并重试 */
                hPipe = ksp_ensure_pipe(prov);
                if (hPipe != INVALID_HANDLE_VALUE) {
                    ipc_ret = ksp_ipc_call(hPipe, CMD_KSP_GET_KEY_INFO, req, &resp, &rv);
                }
            } else {
                ksp_log("KspOpenKey: PIN login failed or cancelled");
                /* 使用默认值继续（允许 key open，签名时再处理） */
                rv = 1;
            }
        }

        if (ipc_ret == 0 && rv == 0) {
            /* Parse algorithm and bits from response */
            if (resp) {
                const char *alg_pos = strstr(resp, "\"algorithm\":\"");
                if (alg_pos) {
                    alg_pos += 13;
                    if (strncmp(alg_pos, "RSA", 3) == 0) {
                        wcscpy_s(key->szAlgorithm, 64, BCRYPT_RSA_ALGORITHM);
                    } else if (strncmp(alg_pos, "ECDSA", 5) == 0) {
                        wcscpy_s(key->szAlgorithm, 64, BCRYPT_ECDSA_ALGORITHM);
                    }
                }
                const char *bits_pos = strstr(resp, "\"bits\":");
                if (bits_pos) {
                    key->dwKeyBits = (DWORD)strtoul(bits_pos + 7, NULL, 10);
                }
                /* Parse and cache public_key (base64 SubjectPublicKeyInfo DER) */
                DWORD pub_len = 0;
                BYTE *pub_der = json_get_b64_field(resp, "public_key", &pub_len);
                if (pub_der && pub_len > 0) {
                    key->pbPublicKeyInfo = pub_der;
                    key->cbPublicKeyInfo = pub_len;
                    ksp_log("KspOpenKey: public_key cached (len=%u)", pub_len);
                }
                free(resp);
            }
        } else {
            /* Backend not available or login failed, use defaults */
            ksp_log("KspOpenKey: backend not available, using defaults (RSA/2048)");
            wcscpy_s(key->szAlgorithm, 64, BCRYPT_RSA_ALGORITHM);
            key->dwKeyBits = 2048;
            if (resp) free(resp);
        }
    }

    *phKey = (NCRYPT_KEY_HANDLE)key;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI KspFreeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey)
{
    OPENCERT_KSP_KEY *key = (OPENCERT_KSP_KEY *)hKey;
    if (!key || key->dwMagic != KSP_KEY_MAGIC)
        return NTE_INVALID_HANDLE;

    if (key->pbPublicKeyInfo) free(key->pbPublicKeyInfo);
    key->dwMagic = 0;
    HeapFree(GetProcessHeap(), 0, key);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI KspGetKeyProperty(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    LPCWSTR pszProperty,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    OPENCERT_KSP_KEY *key = (OPENCERT_KSP_KEY *)hKey;
    if (!key || key->dwMagic != KSP_KEY_MAGIC)
        return NTE_INVALID_HANDLE;
    if (!pszProperty || !pcbResult)
        return NTE_INVALID_PARAMETER;

    ksp_log("KspGetKeyProperty: property=%ls, cbOutput=%u", pszProperty, cbOutput);

    /* NCRYPT_ALGORITHM_PROPERTY */
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0) {
        DWORD needed = (DWORD)((wcslen(key->szAlgorithm) + 1) * sizeof(WCHAR));
        *pcbResult = needed;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < needed) return NTE_BUFFER_TOO_SMALL;
        memcpy(pbOutput, key->szAlgorithm, needed);
        return ERROR_SUCCESS;
    }

    /* NCRYPT_LENGTH_PROPERTY (key length in bits) */
    if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD *)pbOutput = key->dwKeyBits;
        return ERROR_SUCCESS;
    }

    /* NCRYPT_NAME_PROPERTY (container name) */
    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        DWORD needed = (DWORD)((wcslen(key->szContainer) + 1) * sizeof(WCHAR));
        *pcbResult = needed;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < needed) return NTE_BUFFER_TOO_SMALL;
        memcpy(pbOutput, key->szContainer, needed);
        return ERROR_SUCCESS;
    }

    /* NCRYPT_UNIQUE_NAME_PROPERTY */
    if (wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0) {
        DWORD needed = (DWORD)((wcslen(key->szContainer) + 1) * sizeof(WCHAR));
        *pcbResult = needed;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < needed) return NTE_BUFFER_TOO_SMALL;
        memcpy(pbOutput, key->szContainer, needed);
        return ERROR_SUCCESS;
    }

    /* NCRYPT_IMPL_TYPE_PROPERTY */
    if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD *)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG;
        return ERROR_SUCCESS;
    }

    /* NCRYPT_EXPORT_POLICY_PROPERTY - 密钥导出策略 */
    if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        /* 不允许导出私钥（密钥在后端管理） */
        *(DWORD *)pbOutput = 0;
        return ERROR_SUCCESS;
    }

    /* NCRYPT_KEY_USAGE_PROPERTY - 密钥用途 */
    if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        /* 允许签名和解密 */
        *(DWORD *)pbOutput = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
        return ERROR_SUCCESS;
    }

    /* NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY */
    if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD *)pbOutput = 0;  /* 不支持安全描述符 */
        return ERROR_SUCCESS;
    }

    /* NCRYPT_PROVIDER_HANDLE_PROPERTY - 返回 Provider 句柄 */
    if (wcscmp(pszProperty, NCRYPT_PROVIDER_HANDLE_PROPERTY) == 0) {
        *pcbResult = sizeof(NCRYPT_PROV_HANDLE);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(NCRYPT_PROV_HANDLE)) return NTE_BUFFER_TOO_SMALL;
        *(NCRYPT_PROV_HANDLE *)pbOutput = (NCRYPT_PROV_HANDLE)key->pProvider;
        return ERROR_SUCCESS;
    }

    /* NCRYPT_WINDOW_HANDLE_PROPERTY */
    if (wcscmp(pszProperty, NCRYPT_WINDOW_HANDLE_PROPERTY) == 0) {
        *pcbResult = sizeof(HWND);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(HWND)) return NTE_BUFFER_TOO_SMALL;
        *(HWND *)pbOutput = NULL;
        return ERROR_SUCCESS;
    }

    /* NCRYPT_ALGORITHM_GROUP_PROPERTY */
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0) {
        const WCHAR *group = (wcscmp(key->szAlgorithm, BCRYPT_RSA_ALGORITHM) == 0)
            ? NCRYPT_RSA_ALGORITHM_GROUP : NCRYPT_ECDSA_ALGORITHM_GROUP;
        DWORD needed = (DWORD)((wcslen(group) + 1) * sizeof(WCHAR));
        *pcbResult = needed;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < needed) return NTE_BUFFER_TOO_SMALL;
        memcpy(pbOutput, group, needed);
        return ERROR_SUCCESS;
    }

    /* NCRYPT_BLOCK_LENGTH_PROPERTY */
    if (wcscmp(pszProperty, NCRYPT_BLOCK_LENGTH_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD *)pbOutput = key->dwKeyBits / 8;
        return ERROR_SUCCESS;
    }

    /* Public key blob via GetProperty */
    if (wcscmp(pszProperty, BCRYPT_RSAPUBLIC_BLOB) == 0 ||
        wcscmp(pszProperty, BCRYPT_PUBLIC_KEY_BLOB) == 0 ||
        wcscmp(pszProperty, L"PublicKeyBlob") == 0) {
        if (!key->pbPublicKeyInfo || key->cbPublicKeyInfo == 0) return NTE_NOT_SUPPORTED;
        DWORD blob_len = 0;
        BYTE *blob = spki_to_rsapublic_blob(key->pbPublicKeyInfo, key->cbPublicKeyInfo, &blob_len);
        if (!blob) return NTE_INTERNAL_ERROR;
        *pcbResult = blob_len;
        if (!pbOutput) { free(blob); return ERROR_SUCCESS; }
        if (cbOutput < blob_len) { free(blob); return NTE_BUFFER_TOO_SMALL; }
        memcpy(pbOutput, blob, blob_len); free(blob);
        return ERROR_SUCCESS;
    }

    ksp_log("KspGetKeyProperty: unsupported property=%ls", pszProperty);
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspSignHash(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    VOID *pPaddingInfo,
    PBYTE pbHashValue,
    DWORD cbHashValue,
    PBYTE pbSignature,
    DWORD cbSignature,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    OPENCERT_KSP_KEY *key = (OPENCERT_KSP_KEY *)hKey;
    if (!key || key->dwMagic != KSP_KEY_MAGIC)
        return NTE_INVALID_HANDLE;
    if (!pbHashValue || cbHashValue == 0 || !pcbResult)
        return NTE_INVALID_PARAMETER;

    ksp_log("KspSignHash: container=%ls, hashLen=%u, sigBufLen=%u, flags=0x%X",
            key->szContainer, cbHashValue, cbSignature, dwFlags);

    OPENCERT_KSP_PROVIDER *prov = key->pProvider;
    HANDLE hPipe = ksp_ensure_pipe(prov);
    if (hPipe == INVALID_HANDLE_VALUE) {
        ksp_log("KspSignHash: FAILED - IPC pipe not available (client-card not running?)");
        return NTE_DEVICE_NOT_FOUND;
    }

    /* Convert container to UTF-8 */
    char container_utf8[512];
    WideCharToMultiByte(CP_UTF8, 0, key->szContainer, -1,
                       container_utf8, sizeof(container_utf8), NULL, NULL);

    /* Determine algorithm and hash algorithm */
    const char *algorithm = "RSA";
    const char *hash_alg = "SHA256";

    if (wcscmp(key->szAlgorithm, BCRYPT_ECDSA_ALGORITHM) == 0 ||
        wcscmp(key->szAlgorithm, BCRYPT_ECDSA_P256_ALGORITHM) == 0 ||
        wcscmp(key->szAlgorithm, BCRYPT_ECDSA_P384_ALGORITHM) == 0) {
        algorithm = "ECDSA";
    }

    /* Determine hash algorithm from hash length */
    switch (cbHashValue) {
    case 32: hash_alg = "SHA256"; break;
    case 48: hash_alg = "SHA384"; break;
    case 64: hash_alg = "SHA512"; break;
    case 20: hash_alg = "SHA1"; break;
    }

    /* Also check padding info for hash algorithm */
    if (pPaddingInfo && (dwFlags & BCRYPT_PAD_PKCS1)) {
        BCRYPT_PKCS1_PADDING_INFO *pkcs1 = (BCRYPT_PKCS1_PADDING_INFO *)pPaddingInfo;
        if (pkcs1->pszAlgId) {
            if (wcscmp(pkcs1->pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0) hash_alg = "SHA256";
            else if (wcscmp(pkcs1->pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0) hash_alg = "SHA384";
            else if (wcscmp(pkcs1->pszAlgId, BCRYPT_SHA512_ALGORITHM) == 0) hash_alg = "SHA512";
            else if (wcscmp(pkcs1->pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0) hash_alg = "SHA1";
        }
    }

    /* Encode hash data as base64 */
    char *data_b64 = b64_encode(pbHashValue, cbHashValue);
    if (!data_b64) return NTE_NO_MEMORY;

    /* Build JSON request */
    char *req = (char *)malloc(strlen(container_utf8) + strlen(data_b64) + 256);
    if (!req) { free(data_b64); return NTE_NO_MEMORY; }

    sprintf(req, "{\"container\":\"%s\",\"algorithm\":\"%s\",\"hash_alg\":\"%s\",\"data\":\"%s\",\"flags\":%u}",
            container_utf8, algorithm, hash_alg, data_b64, dwFlags);
    free(data_b64);

    /* Call backend */
    char *resp = NULL;
    DWORD rv = 0;
    int ret = ksp_ipc_call(hPipe, CMD_KSP_SIGN, req, &resp, &rv);

    /* 如果后端返回 CKR_USER_NOT_LOGGED_IN，弹出 PIN 输入框并重试 */
    if (ret == 0 && rv == CKR_USER_NOT_LOGGED_IN) {
        if (resp) { free(resp); resp = NULL; }
        ksp_log("KspSignHash: Slot not logged in, prompting for PIN");

        if (ksp_handle_login_required(prov, key->szContainer, NULL, NULL, key->hWndParent) == 0) {
            /* Login 成功，重新连接并重试签名 */
            hPipe = ksp_ensure_pipe(prov);
            if (hPipe != INVALID_HANDLE_VALUE) {
                ret = ksp_ipc_call(hPipe, CMD_KSP_SIGN, req, &resp, &rv);
            } else {
                free(req);
                return NTE_DEVICE_NOT_FOUND;
            }
        } else {
            free(req);
            return NTE_INTERNAL_ERROR;
        }
    }

    free(req);

    if (ret != 0 || rv != 0) {
        if (resp) free(resp);
        /* Try reconnect once */
        prov->hPipe = INVALID_HANDLE_VALUE;
        return NTE_INTERNAL_ERROR;
    }

    /* Parse signature from response */
    DWORD sig_len = 0;
    BYTE *sig_data = json_get_b64_field(resp, "signature", &sig_len);
    free(resp);

    if (!sig_data || sig_len == 0) {
        if (sig_data) free(sig_data);
        return NTE_INTERNAL_ERROR;
    }

    *pcbResult = sig_len;

    /* If pbSignature is NULL, caller is querying the size */
    if (!pbSignature) {
        free(sig_data);
        return ERROR_SUCCESS;
    }

    if (cbSignature < sig_len) {
        free(sig_data);
        return NTE_BUFFER_TOO_SMALL;
    }

    memcpy(pbSignature, sig_data, sig_len);
    free(sig_data);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI KspDecrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
    DWORD cbInput,
    VOID *pPaddingInfo,
    PBYTE pbOutput,
    DWORD cbOutput,
    DWORD *pcbResult,
    DWORD dwFlags)
{
    OPENCERT_KSP_KEY *key = (OPENCERT_KSP_KEY *)hKey;
    if (!key || key->dwMagic != KSP_KEY_MAGIC)
        return NTE_INVALID_HANDLE;
    if (!pbInput || cbInput == 0 || !pcbResult)
        return NTE_INVALID_PARAMETER;

    OPENCERT_KSP_PROVIDER *prov = key->pProvider;
    HANDLE hPipe = ksp_ensure_pipe(prov);
    if (hPipe == INVALID_HANDLE_VALUE)
        return NTE_DEVICE_NOT_FOUND;

    char container_utf8[512];
    WideCharToMultiByte(CP_UTF8, 0, key->szContainer, -1,
                       container_utf8, sizeof(container_utf8), NULL, NULL);

    char *data_b64 = b64_encode(pbInput, cbInput);
    if (!data_b64) return NTE_NO_MEMORY;

    char *req = (char *)malloc(strlen(container_utf8) + strlen(data_b64) + 256);
    if (!req) { free(data_b64); return NTE_NO_MEMORY; }

    sprintf(req, "{\"container\":\"%s\",\"algorithm\":\"RSA\",\"data\":\"%s\",\"flags\":%u}",
            container_utf8, data_b64, dwFlags);
    free(data_b64);

    char *resp = NULL;
    DWORD rv = 0;
    int ret = ksp_ipc_call(hPipe, CMD_KSP_DECRYPT, req, &resp, &rv);
    free(req);

    if (ret != 0 || rv != 0) {
        if (resp) free(resp);
        prov->hPipe = INVALID_HANDLE_VALUE;
        return NTE_INTERNAL_ERROR;
    }

    DWORD plain_len = 0;
    BYTE *plain_data = json_get_b64_field(resp, "plaintext", &plain_len);
    free(resp);

    if (!plain_data || plain_len == 0) {
        if (plain_data) free(plain_data);
        return NTE_INTERNAL_ERROR;
    }

    *pcbResult = plain_len;
    if (!pbOutput) {
        free(plain_data);
        return ERROR_SUCCESS;
    }
    if (cbOutput < plain_len) {
        free(plain_data);
        return NTE_BUFFER_TOO_SMALL;
    }

    memcpy(pbOutput, plain_data, plain_len);
    free(plain_data);
    return ERROR_SUCCESS;
}

/* ---- Stub functions (not implemented but required) ---- */

static SECURITY_STATUS WINAPI KspSetKeyProperty(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey,
    LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags)
{
    ksp_log("KspSetKeyProperty: property=%ls, flags=0x%X", pszProperty ? pszProperty : L"(null)", dwFlags);
    if (pszProperty && wcscmp(pszProperty, NCRYPT_WINDOW_HANDLE_PROPERTY) == 0) {
        OPENCERT_KSP_KEY *key = (OPENCERT_KSP_KEY *)hKey;
        if (key && key->dwMagic == KSP_KEY_MAGIC && pbInput && cbInput >= sizeof(HWND)) {
            key->hWndParent = *(HWND *)pbInput;
            ksp_log("KspSetKeyProperty: stored hWndParent=%p", key->hWndParent);
        }
        return ERROR_SUCCESS;
    }
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspGetProviderProperty(
    NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty,
    PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
    if (!pcbResult) return NTE_INVALID_PARAMETER;

    if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        DWORD needed = (DWORD)((wcslen(OPENCERT_KSP_NAME) + 1) * sizeof(WCHAR));
        *pcbResult = needed;
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < needed) return NTE_BUFFER_TOO_SMALL;
        memcpy(pbOutput, OPENCERT_KSP_NAME, needed);
        return ERROR_SUCCESS;
    }

    if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD *)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG;
        return ERROR_SUCCESS;
    }

    if (wcscmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (!pbOutput) return ERROR_SUCCESS;
        if (cbOutput < sizeof(DWORD)) return NTE_BUFFER_TOO_SMALL;
        *(DWORD *)pbOutput = OPENCERT_KSP_VERSION;
        return ERROR_SUCCESS;
    }

    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspSetProviderProperty(
    NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty,
    PBYTE pbInput, DWORD cbInput, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspCreatePersistedKey(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey,
    LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspFinalizeKey(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspDeleteKey(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspEnumAlgorithms(
    NCRYPT_PROV_HANDLE hProvider, DWORD dwAlgOperations,
    DWORD *pdwAlgCount, NCryptAlgorithmName **ppAlgList, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

/* ---- EnumKeys state management ---- */

typedef struct _KSP_ENUM_STATE {
    DWORD dwMagic;          /* 'ENUM' = 0x454E554D */
    DWORD dwCount;          /* Total number of keys */
    DWORD dwIndex;          /* Current index (next to return) */
    /* Followed by dwCount entries of KSP_ENUM_ENTRY */
} KSP_ENUM_STATE;

typedef struct _KSP_ENUM_ENTRY {
    WCHAR szContainer[256];
    WCHAR szAlgorithm[64];
    DWORD dwKeyBits;
} KSP_ENUM_ENTRY;

#define KSP_ENUM_MAGIC  0x454E554Du  /* "ENUM" */

/* Parse JSON array of keys from IPC response */
static KSP_ENUM_STATE *ksp_parse_enum_response(const char *json)
{
    /* Count keys by counting "container" occurrences */
    DWORD count = 0;
    const char *p = json;
    while ((p = strstr(p, "\"container\":\"")) != NULL) {
        count++;
        p++;
    }

    if (count == 0) return NULL;

    /* Allocate state + entries */
    DWORD alloc_size = sizeof(KSP_ENUM_STATE) + count * sizeof(KSP_ENUM_ENTRY);
    KSP_ENUM_STATE *state = (KSP_ENUM_STATE *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, alloc_size);
    if (!state) return NULL;

    state->dwMagic = KSP_ENUM_MAGIC;
    state->dwCount = count;
    state->dwIndex = 0;

    KSP_ENUM_ENTRY *entries = (KSP_ENUM_ENTRY *)((BYTE *)state + sizeof(KSP_ENUM_STATE));

    /* Parse each key entry */
    p = json;
    DWORD idx = 0;
    while (idx < count && (p = strstr(p, "\"container\":\"")) != NULL) {
        p += 13; /* skip "container":" */
        const char *end = strchr(p, '"');
        if (!end) break;

        /* Extract container name (UTF-8 -> UTF-16) */
        DWORD name_len = (DWORD)(end - p);
        char name_utf8[512];
        if (name_len >= sizeof(name_utf8)) name_len = sizeof(name_utf8) - 1;
        memcpy(name_utf8, p, name_len);
        name_utf8[name_len] = '\0';
        MultiByteToWideChar(CP_UTF8, 0, name_utf8, -1,
                           entries[idx].szContainer, 256);

        /* Extract algorithm */
        const char *alg_pos = strstr(end, "\"algorithm\":\"");
        if (alg_pos && alg_pos < strstr(end, "\"container\":\"")) {
            alg_pos += 13;
            if (strncmp(alg_pos, "RSA", 3) == 0) {
                wcscpy_s(entries[idx].szAlgorithm, 64, BCRYPT_RSA_ALGORITHM);
            } else if (strncmp(alg_pos, "ECDSA", 5) == 0) {
                wcscpy_s(entries[idx].szAlgorithm, 64, BCRYPT_ECDSA_ALGORITHM);
            } else {
                wcscpy_s(entries[idx].szAlgorithm, 64, BCRYPT_RSA_ALGORITHM);
            }
        } else if (alg_pos) {
            alg_pos += 13;
            if (strncmp(alg_pos, "RSA", 3) == 0) {
                wcscpy_s(entries[idx].szAlgorithm, 64, BCRYPT_RSA_ALGORITHM);
            } else if (strncmp(alg_pos, "ECDSA", 5) == 0) {
                wcscpy_s(entries[idx].szAlgorithm, 64, BCRYPT_ECDSA_ALGORITHM);
            } else {
                wcscpy_s(entries[idx].szAlgorithm, 64, BCRYPT_RSA_ALGORITHM);
            }
        }

        /* Extract bits */
        const char *bits_pos = strstr(end, "\"bits\":");
        if (bits_pos) {
            entries[idx].dwKeyBits = (DWORD)strtoul(bits_pos + 7, NULL, 10);
        }

        p = end + 1;
        idx++;
    }

    state->dwCount = idx; /* Actual parsed count */
    return state;
}

static SECURITY_STATUS WINAPI KspEnumKeys(
    NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszScope,
    NCryptKeyName **ppKeyName, PVOID *ppEnumState, DWORD dwFlags)
{
    OPENCERT_KSP_PROVIDER *prov = (OPENCERT_KSP_PROVIDER *)hProvider;
    if (!prov || prov->dwMagic != KSP_PROVIDER_MAGIC)
        return NTE_INVALID_HANDLE;
    if (!ppKeyName || !ppEnumState)
        return NTE_INVALID_PARAMETER;

    KSP_ENUM_STATE *state = (KSP_ENUM_STATE *)*ppEnumState;

    /* First call: fetch all keys from backend */
    if (!state) {
        HANDLE hPipe = ksp_ensure_pipe(prov);
        if (hPipe == INVALID_HANDLE_VALUE) {
            ksp_log("KspEnumKeys: IPC not available");
            return NTE_DEVICE_NOT_FOUND;
        }

        char *resp = NULL;
        DWORD rv = 0;
        int ret = ksp_ipc_call(hPipe, CMD_KSP_ENUM_KEYS, "{}", &resp, &rv);
        if (ret != 0 || rv != 0) {
            if (resp) free(resp);
            prov->hPipe = INVALID_HANDLE_VALUE;
            ksp_log("KspEnumKeys: IPC call failed (ret=%d, rv=%u)", ret, rv);
            return NTE_INTERNAL_ERROR;
        }

        if (!resp) {
            ksp_log("KspEnumKeys: empty response");
            return NTE_NOT_FOUND;
        }

        state = ksp_parse_enum_response(resp);
        free(resp);

        if (!state || state->dwCount == 0) {
            if (state) HeapFree(GetProcessHeap(), 0, state);
            ksp_log("KspEnumKeys: no keys found");
            return NTE_NOT_FOUND;
        }

        *ppEnumState = state;
        ksp_log("KspEnumKeys: fetched %u keys from backend", state->dwCount);
    }

    /* Check if we've exhausted all entries */
    if (state->dwMagic != KSP_ENUM_MAGIC || state->dwIndex >= state->dwCount) {
        /* Enumeration complete - free state */
        HeapFree(GetProcessHeap(), 0, state);
        *ppEnumState = NULL;
        return NTE_NO_MORE_ITEMS;
    }

    /* Return current entry */
    KSP_ENUM_ENTRY *entries = (KSP_ENUM_ENTRY *)((BYTE *)state + sizeof(KSP_ENUM_STATE));
    KSP_ENUM_ENTRY *entry = &entries[state->dwIndex];

    /* Allocate NCryptKeyName structure (caller frees via NCryptFreeBuffer) */
    DWORD name_len = (DWORD)((wcslen(entry->szContainer) + 1) * sizeof(WCHAR));
    DWORD alg_len = (DWORD)((wcslen(entry->szAlgorithm) + 1) * sizeof(WCHAR));
    DWORD total = sizeof(NCryptKeyName) + name_len + alg_len;

    NCryptKeyName *keyName = (NCryptKeyName *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (!keyName) return NTE_NO_MEMORY;

    /* Layout: [NCryptKeyName][name_wstr][alg_wstr] */
    BYTE *ptr = (BYTE *)keyName + sizeof(NCryptKeyName);
    keyName->pszName = (LPWSTR)ptr;
    memcpy(ptr, entry->szContainer, name_len);
    ptr += name_len;

    keyName->pszAlgid = (LPWSTR)ptr;
    memcpy(ptr, entry->szAlgorithm, alg_len);

    keyName->dwLegacyKeySpec = AT_KEYEXCHANGE;
    keyName->dwFlags = 0;

    *ppKeyName = keyName;
    state->dwIndex++;

    ksp_log("KspEnumKeys: returning key[%u] = %ls (%ls)",
            state->dwIndex - 1, entry->szContainer, entry->szAlgorithm);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI KspImportKey(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hImportKey,
    LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList,
    NCRYPT_KEY_HANDLE *phKey, PBYTE pbData, DWORD cbData, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspExportKey(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey,
    NCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType,
    NCryptBufferDesc *pParameterList,
    PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
    OPENCERT_KSP_KEY *key = (OPENCERT_KSP_KEY *)hKey;
    if (!key || key->dwMagic != KSP_KEY_MAGIC) return NTE_INVALID_HANDLE;
    if (!pszBlobType || !pcbResult) return NTE_INVALID_PARAMETER;
    ksp_log("KspExportKey: blobType=%ls, flags=0x%X", pszBlobType, dwFlags);
    if (wcscmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) != 0 &&
        wcscmp(pszBlobType, BCRYPT_PUBLIC_KEY_BLOB) != 0 &&
        wcscmp(pszBlobType, L"PublicKeyBlob") != 0) {
        return NTE_NOT_SUPPORTED;
    }
    if (!key->pbPublicKeyInfo || key->cbPublicKeyInfo == 0) return NTE_NOT_SUPPORTED;
    DWORD blob_len = 0;
    BYTE *blob = spki_to_rsapublic_blob(key->pbPublicKeyInfo, key->cbPublicKeyInfo, &blob_len);
    if (!blob) return NTE_INTERNAL_ERROR;
    *pcbResult = blob_len;
    if (!pbOutput) { free(blob); return ERROR_SUCCESS; }
    if (cbOutput < blob_len) { free(blob); return NTE_BUFFER_TOO_SMALL; }
    memcpy(pbOutput, blob, blob_len); free(blob);
    ksp_log("KspExportKey: SUCCESS (len=%u)", blob_len);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI KspEncrypt(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo,
    PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspVerifySignature(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey,
    VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue,
    PBYTE pbSignature, DWORD cbSignature, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspIsAlgSupported(
    NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszAlgId, DWORD dwFlags)
{
    if (wcscmp(pszAlgId, BCRYPT_RSA_ALGORITHM) == 0 ||
        wcscmp(pszAlgId, BCRYPT_ECDSA_ALGORITHM) == 0 ||
        wcscmp(pszAlgId, BCRYPT_ECDSA_P256_ALGORITHM) == 0 ||
        wcscmp(pszAlgId, BCRYPT_ECDSA_P384_ALGORITHM) == 0) {
        return ERROR_SUCCESS;
    }
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspFreeBuffer(PVOID pvInput)
{
    if (pvInput)
        HeapFree(GetProcessHeap(), 0, pvInput);
    return ERROR_SUCCESS;
}

static SECURITY_STATUS WINAPI KspPromptUser(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey,
    LPCWSTR pszOperation, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspNotifyChangeKey(
    NCRYPT_PROV_HANDLE hProvider, HANDLE *phEvent, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspSecretAgreement(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hPrivKey,
    NCRYPT_KEY_HANDLE hPubKey, NCRYPT_SECRET_HANDLE *phAgreedSecret, DWORD dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspDeriveKey(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret,
    LPCWSTR pwszKDF, NCryptBufferDesc *pParameterList,
    PBYTE pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags)
{
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS WINAPI KspFreeSecret(
    NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret)
{
    return NTE_NOT_SUPPORTED;
}

/* ---- Function Table ---- */

static OPENCERT_KSP_FUNCTION_TABLE g_KspFunctionTable = {
    {1, 0},                                 /* Version (major=1, minor=0) */
    KspOpenProvider,                        /* OpenProvider */
    KspOpenKey,                             /* OpenKey */
    KspCreatePersistedKey,                  /* CreatePersistedKey */
    KspGetProviderProperty,                 /* GetProviderProperty */
    KspGetKeyProperty,                      /* GetKeyProperty */
    KspSetProviderProperty,                 /* SetProviderProperty */
    KspSetKeyProperty,                      /* SetKeyProperty */
    KspFinalizeKey,                         /* FinalizeKey */
    KspDeleteKey,                           /* DeleteKey */
    KspFreeProvider,                        /* FreeProvider */
    KspFreeKey,                             /* FreeKey */
    KspFreeBuffer,                          /* FreeBuffer */
    KspEncrypt,                             /* Encrypt */
    KspDecrypt,                             /* Decrypt */
    KspIsAlgSupported,                      /* IsAlgSupported */
    KspEnumAlgorithms,                      /* EnumAlgorithms */
    KspEnumKeys,                            /* EnumKeys */
    KspImportKey,                           /* ImportKey */
    KspExportKey,                           /* ExportKey */
    KspSignHash,                            /* SignHash */
    KspVerifySignature,                     /* VerifySignature */
    KspPromptUser,                          /* PromptUser */
    KspNotifyChangeKey,                     /* NotifyChangeKey */
    KspSecretAgreement,                     /* SecretAgreement */
    KspDeriveKey,                           /* DeriveKey */
    KspFreeSecret                           /* FreeSecret */
};

/* ---- DLL Export: GetKeyStorageInterface ---- */

__declspec(dllexport)
NTSTATUS WINAPI GetKeyStorageInterface(
    LPCWSTR pszProviderName,
    OPENCERT_KSP_FUNCTION_TABLE **ppFunctionTable,
    DWORD dwFlags)
{
    ksp_log("GetKeyStorageInterface called: name=%ls, ppTable=%p, flags=0x%X",
            pszProviderName ? pszProviderName : L"(null)",
            (void*)ppFunctionTable, dwFlags);

    if (!ppFunctionTable) {
        ksp_log("  -> STATUS_INVALID_PARAMETER (ppFunctionTable is NULL)");
        return STATUS_INVALID_PARAMETER;
    }

    *ppFunctionTable = &g_KspFunctionTable;
    ksp_log("  -> STATUS_SUCCESS, table=%p, version=%d.%d",
            (void*)&g_KspFunctionTable,
            g_KspFunctionTable.Version.MajorVersion,
            g_KspFunctionTable.Version.MinorVersion);
    return STATUS_SUCCESS;
}

/* ---- DLL Entry Point ---- */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        ksp_log("DllMain: DLL_PROCESS_ATTACH (pid=%u)", GetCurrentProcessId());
        break;
    case DLL_PROCESS_DETACH:
        ksp_log("DllMain: DLL_PROCESS_DETACH (pid=%u)", GetCurrentProcessId());
        break;
    }
    return TRUE;
}
