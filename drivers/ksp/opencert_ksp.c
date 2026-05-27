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

    while (retries-- > 0) {
        h = CreateFileA(
            IPC_PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL
        );
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(h, &mode, NULL, NULL);
            return h;
        }
        Sleep(500);
    }
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

    /* Send frame: Magic + Cmd + Len + Payload */
    BYTE header[IPC_HEADER_SIZE];
    DWORD magic_be = u32_to_be(IPC_MAGIC);
    DWORD cmd_be = u32_to_be(cmd);
    DWORD len_be = u32_to_be(req_len);
    memcpy(header + 0, &magic_be, 4);
    memcpy(header + 4, &cmd_be, 4);
    memcpy(header + 8, &len_be, 4);

    if (raw_write(hPipe, header, IPC_HEADER_SIZE) != 0)
        return -1;
    if (req_len > 0 && raw_write(hPipe, req_json, req_len) != 0)
        return -1;

    /* Receive response */
    BYTE resp_header[IPC_HEADER_SIZE];
    if (raw_read(hPipe, resp_header, IPC_HEADER_SIZE) != 0)
        return -1;

    DWORD resp_magic, resp_cmd, resp_len;
    memcpy(&resp_magic, resp_header + 0, 4); resp_magic = be_to_u32(resp_magic);
    memcpy(&resp_cmd, resp_header + 4, 4);   resp_cmd = be_to_u32(resp_cmd);
    memcpy(&resp_len, resp_header + 8, 4);   resp_len = be_to_u32(resp_len);

    if (resp_magic != IPC_MAGIC || resp_len > IPC_MAX_PAYLOAD)
        return -1;

    *out_rv = 0x00000005; /* CKR_GENERAL_ERROR default */
    if (resp_json) *resp_json = NULL;

    if (resp_len > 0) {
        char *buf = (char *)malloc(resp_len + 1);
        if (!buf) return -1;
        if (raw_read(hPipe, buf, resp_len) != 0) {
            free(buf);
            return -1;
        }
        buf[resp_len] = '\0';

        /* Parse "rv" field */
        const char *rv_pos = strstr(buf, "\"rv\":");
        if (rv_pos) *out_rv = (DWORD)strtoul(rv_pos + 5, NULL, 10);

        if (resp_json) {
            *resp_json = buf;
        } else {
            free(buf);
        }
    }
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

/* ---- NCrypt Provider Functions ---- */

static SECURITY_STATUS WINAPI KspOpenProvider(
    NCRYPT_PROV_HANDLE *phProvider,
    LPCWSTR pszProviderName,
    DWORD dwFlags)
{
    OPENCERT_KSP_PROVIDER *prov = (OPENCERT_KSP_PROVIDER *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OPENCERT_KSP_PROVIDER));
    if (!prov) return NTE_NO_MEMORY;

    prov->cbLength = sizeof(OPENCERT_KSP_PROVIDER);
    prov->dwMagic = KSP_PROVIDER_MAGIC;
    prov->dwFlags = dwFlags;
    prov->hPipe = INVALID_HANDLE_VALUE;

    *phProvider = (NCRYPT_PROV_HANDLE)prov;
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
        if (ksp_ipc_call(hPipe, CMD_KSP_GET_KEY_INFO, req, &resp, &rv) == 0 && rv == 0) {
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
                free(resp);
            }
        } else {
            /* Backend not available, still allow key open (lazy connect) */
            wcscpy_s(key->szAlgorithm, 64, BCRYPT_RSA_ALGORITHM);
            key->dwKeyBits = 2048;
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

    OPENCERT_KSP_PROVIDER *prov = key->pProvider;
    HANDLE hPipe = ksp_ensure_pipe(prov);
    if (hPipe == INVALID_HANDLE_VALUE)
        return NTE_DEVICE_NOT_FOUND;

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

static SECURITY_STATUS WINAPI KspEnumKeys(
    NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszScope,
    NCryptKeyName **ppKeyName, PVOID *ppEnumState, DWORD dwFlags)
{
    /* TODO: Implement key enumeration via IPC CmdKSPEnumKeys */
    return NTE_NOT_SUPPORTED;
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
    return NTE_NOT_SUPPORTED;
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
    if (!ppFunctionTable)
        return STATUS_INVALID_PARAMETER;

    *ppFunctionTable = &g_KspFunctionTable;
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
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
