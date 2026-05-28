/*
 * opencert_ksp.h - OpenCert Key Storage Provider (KSP)
 *
 * Windows CNG KSP interface. Forwards sign/decrypt to client-card via IPC.
 *
 * Ref:
 *   https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-provider-functions
 */

#ifndef OPENCERT_KSP_H
#define OPENCERT_KSP_H

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>

/* NTSTATUS codes (may not be defined without ntstatus.h) */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED    ((NTSTATUS)0xC00000BBL)
#endif

/* NTE error codes (should be in winerror.h but just in case) */
#ifndef NTE_DEVICE_NOT_FOUND
#define NTE_DEVICE_NOT_FOUND    ((SECURITY_STATUS)0x80090035L)
#endif
#ifndef NTE_INTERNAL_ERROR
#define NTE_INTERNAL_ERROR      ((SECURITY_STATUS)0x80090020L)
#endif
#ifndef NTE_NO_MORE_ITEMS
#define NTE_NO_MORE_ITEMS       ((SECURITY_STATUS)0x8009002AL)
#endif
#ifndef NTE_NOT_FOUND
#define NTE_NOT_FOUND           ((SECURITY_STATUS)0x80090011L)
#endif
#ifndef NTE_NO_MEMORY
#define NTE_NO_MEMORY           ((SECURITY_STATUS)0x8009000EL)
#endif

/* NCrypt key usage flags (should be in ncrypt.h but just in case) */
#ifndef NCRYPT_ALLOW_SIGNING_FLAG
#define NCRYPT_ALLOW_SIGNING_FLAG   0x00000002
#endif
#ifndef NCRYPT_ALLOW_DECRYPT_FLAG
#define NCRYPT_ALLOW_DECRYPT_FLAG   0x00000001
#endif

/* ---- KSP Identity ---- */
#define OPENCERT_KSP_NAME       L"OpenCert Key Storage Provider"
#define OPENCERT_KSP_VERSION    1

/* ---- IPC Command Codes (match Go backend protocol.go) ---- */
#define CMD_KSP_ENUM_KEYS       0x0200u
#define CMD_KSP_GET_KEY_INFO    0x0201u
#define CMD_KSP_SIGN            0x0202u
#define CMD_KSP_DECRYPT         0x0203u
#define CMD_KSP_LOGIN           0x0204u

/* ---- PKCS#11 Return Values (used in IPC responses) ---- */
#define CKR_OK                      0x00000000u
#define CKR_USER_NOT_LOGGED_IN      0x00000101u
#define CKR_PIN_INCORRECT           0x000000A0u
#define CKR_PIN_LOCKED              0x000000A4u

/* ---- IPC Protocol Constants ---- */
#define IPC_MAGIC               0x504B3131u  /* "PK11" */
#define IPC_HEADER_SIZE         12
#define IPC_MAX_PAYLOAD         (4 * 1024 * 1024)
#define IPC_PIPE_NAME           "\\\\.\\pipe\\clients"

/* ---- Internal Structures ---- */

typedef struct _OPENCERT_KSP_PROVIDER {
    DWORD       cbLength;
    DWORD       dwMagic;
    DWORD       dwFlags;
    HANDLE      hPipe;
} OPENCERT_KSP_PROVIDER;

#define KSP_PROVIDER_MAGIC  0x4B535031  /* "KSP1" */

typedef struct _OPENCERT_KSP_KEY {
    DWORD       cbLength;
    DWORD       dwMagic;
    WCHAR       szContainer[256];
    WCHAR       szAlgorithm[64];
    DWORD       dwKeyBits;
    DWORD       dwFlags;
    OPENCERT_KSP_PROVIDER *pProvider;
    /* SubjectPublicKeyInfo DER（从后端 IPC 响应中获取，用于公钥导出） */
    BYTE        *pbPublicKeyInfo;
    DWORD       cbPublicKeyInfo;
} OPENCERT_KSP_KEY;

#define KSP_KEY_MAGIC       0x4B455931  /* "KEY1" */

/* ---- NCRYPT_KEY_STORAGE_FUNCTION_TABLE ----
 * This structure is defined in ncrypt_provider.h (Windows WDK) but not
 * available in standard Windows SDK. We always define it here.
 * Note: The SDK may define NCRYPT_KEY_STORAGE_INTERFACE_VERSION macro
 * but NOT the actual struct, so we use our own guard.
 */
#ifndef _OPENCERT_KSP_FUNC_TABLE_DEFINED
#define _OPENCERT_KSP_FUNC_TABLE_DEFINED

typedef struct _OPENCERT_KSP_FUNCTION_TABLE {
    BCRYPT_INTERFACE_VERSION    Version;
    SECURITY_STATUS (WINAPI *OpenProvider)(NCRYPT_PROV_HANDLE *phProvider, LPCWSTR pszProviderName, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *OpenKey)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *CreatePersistedKey)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *GetProviderProperty)(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *GetKeyProperty)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *SetProviderProperty)(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *SetKeyProperty)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszProperty, PBYTE pbInput, DWORD cbInput, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *FinalizeKey)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *DeleteKey)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *FreeProvider)(NCRYPT_PROV_HANDLE hProvider);
    SECURITY_STATUS (WINAPI *FreeKey)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey);
    SECURITY_STATUS (WINAPI *FreeBuffer)(PVOID pvInput);
    SECURITY_STATUS (WINAPI *Encrypt)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *Decrypt)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *IsAlgSupported)(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszAlgId, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *EnumAlgorithms)(NCRYPT_PROV_HANDLE hProvider, DWORD dwAlgOperations, DWORD *pdwAlgCount, NCryptAlgorithmName **ppAlgList, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *EnumKeys)(NCRYPT_PROV_HANDLE hProvider, LPCWSTR pszScope, NCryptKeyName **ppKeyName, PVOID *ppEnumState, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *ImportKey)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList, NCRYPT_KEY_HANDLE *phKey, PBYTE pbData, DWORD cbData, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *ExportKey)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, NCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, NCryptBufferDesc *pParameterList, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *SignHash)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD *pcbResult, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *VerifySignature)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, VOID *pPaddingInfo, PBYTE pbHashValue, DWORD cbHashValue, PBYTE pbSignature, DWORD cbSignature, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *PromptUser)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, LPCWSTR pszOperation, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *NotifyChangeKey)(NCRYPT_PROV_HANDLE hProvider, HANDLE *phEvent, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *SecretAgreement)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hPrivKey, NCRYPT_KEY_HANDLE hPubKey, NCRYPT_SECRET_HANDLE *phAgreedSecret, DWORD dwFlags);
    SECURITY_STATUS (WINAPI *DeriveKey)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret, LPCWSTR pwszKDF, NCryptBufferDesc *pParameterList, PBYTE pbDerivedKey, DWORD cbDerivedKey, DWORD *pcbResult, ULONG dwFlags);
    SECURITY_STATUS (WINAPI *FreeSecret)(NCRYPT_PROV_HANDLE hProvider, NCRYPT_SECRET_HANDLE hSharedSecret);
} OPENCERT_KSP_FUNCTION_TABLE;

#endif /* _OPENCERT_KSP_FUNC_TABLE_DEFINED */

/* ---- DLL Export ---- */

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport)
NTSTATUS WINAPI GetKeyStorageInterface(
    LPCWSTR pszProviderName,
    OPENCERT_KSP_FUNCTION_TABLE **ppFunctionTable,
    DWORD dwFlags
);

#ifdef __cplusplus
}
#endif

/* ---- IPC Helpers ---- */
HANDLE ksp_ipc_connect(void);
void ksp_ipc_disconnect(HANDLE hPipe);
int ksp_ipc_call(HANDLE hPipe, DWORD cmd,
                 const char *req_json,
                 char **resp_json, DWORD *out_rv);

#endif /* OPENCERT_KSP_H */
