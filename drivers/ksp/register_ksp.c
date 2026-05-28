/*
 * register_ksp.c - Register OpenCert KSP with CNG
 *
 * This tool uses BCryptAddContextFunctionProvider to properly register
 * the KSP with the CNG configuration system.
 *
 * Must be run as Administrator.
 *
 * Build:
 *   cl /nologo /O2 register_ksp.c /link bcrypt.lib
 */

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

/* These constants may not be in older SDK headers */
#ifndef CRYPT_LOCAL
#define CRYPT_LOCAL     0x00000001
#endif

#ifndef NCRYPT_KEY_STORAGE_INTERFACE
#define NCRYPT_KEY_STORAGE_INTERFACE 0x00010001
#endif

#ifndef CRYPT_DEFAULT
#define CRYPT_DEFAULT   L"Default"
#endif

#define KSP_NAME        L"OpenCert Key Storage Provider"
#define KSP_IMAGE       L"OpenCertKSP.dll"

int wmain(int argc, wchar_t *argv[])
{
    NTSTATUS status;
    BOOL unregister = FALSE;
    CRYPT_CONTEXT_FUNCTION_PROVIDERS *pProviders = NULL;

    if (argc > 1 && (wcscmp(argv[1], L"/u") == 0 || wcscmp(argv[1], L"-u") == 0)) {
        unregister = TRUE;
    }

    printf("=== OpenCert KSP Registration Tool ===\n\n");

    if (unregister) {
        printf("[1] Removing KSP from CNG context...\n");

        /* Remove from default context */
        status = BCryptRemoveContextFunctionProvider(
            CRYPT_LOCAL,
            CRYPT_DEFAULT,
            NCRYPT_KEY_STORAGE_INTERFACE,
            L"KEY_STORAGE",
            KSP_NAME
        );

        if (status == 0) {
            printf("    [OK] Removed from CNG context\n");
        } else {
            printf("    [INFO] Status: 0x%08X (may not have been registered)\n", (unsigned int)status);
        }

        printf("\n[OK] Unregistration complete.\n");
        printf("    Note: Registry entries and DLL are NOT removed.\n");
        printf("    To fully uninstall, also run:\n");
        printf("      reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Providers\\OpenCert Key Storage Provider\" /f\n");
        printf("      del C:\\WINDOWS\\System32\\OpenCertKSP.dll\n");
        return 0;
    }

    /* Register */
    printf("[1] Adding KSP to CNG default context...\n");
    printf("    Provider: %ls\n", KSP_NAME);
    printf("    Interface: NCRYPT_KEY_STORAGE_INTERFACE (0x%08X)\n", NCRYPT_KEY_STORAGE_INTERFACE);
    printf("    Function: KEY_STORAGE\n");
    printf("    Context: Default (CRYPT_LOCAL)\n\n");

    /* Add provider to the default context for KEY_STORAGE function */
    status = BCryptAddContextFunctionProvider(
        CRYPT_LOCAL,                        /* dwTable: local machine */
        CRYPT_DEFAULT,                      /* pszContext: "Default" */
        NCRYPT_KEY_STORAGE_INTERFACE,       /* dwInterface */
        L"KEY_STORAGE",                     /* pszFunction */
        KSP_NAME,                           /* pszProvider */
        CRYPT_PRIORITY_BOTTOM               /* dwPosition: add at bottom */
    );

    if (status == 0) {
        printf("    [OK] Successfully registered!\n");
    } else if (status == (NTSTATUS)0xC0000035L) {
        /* STATUS_OBJECT_NAME_COLLISION - already registered */
        printf("    [OK] Already registered (STATUS_OBJECT_NAME_COLLISION)\n");
    } else {
        printf("    [FAIL] BCryptAddContextFunctionProvider failed: 0x%08X\n", (unsigned int)status);
        if (status == (NTSTATUS)0xC0000022L) {
            printf("    ERROR: Access denied. Please run as Administrator!\n");
        }
        return 1;
    }

    /* Verify by enumerating */
    printf("\n[2] Verifying registration...\n");
    ULONG cbBuffer = 0;
    status = BCryptEnumContextFunctionProviders(
        CRYPT_LOCAL,
        CRYPT_DEFAULT,
        NCRYPT_KEY_STORAGE_INTERFACE,
        L"KEY_STORAGE",
        &cbBuffer,
        &pProviders
    );

    if (status == 0 && pProviders) {
        printf("    Registered KEY_STORAGE providers (%u):\n", pProviders->cProviders);
        for (ULONG i = 0; i < pProviders->cProviders; i++) {
            BOOL isOurs = (wcscmp(pProviders->rgpszProviders[i], KSP_NAME) == 0);
            printf("      [%u] %ls %s\n", i, pProviders->rgpszProviders[i],
                   isOurs ? "<-- OURS" : "");
        }
        BCryptFreeBuffer(pProviders);
    } else {
        printf("    [WARN] Could not enumerate providers: 0x%08X\n", (unsigned int)status);
    }

    printf("\n[3] Testing NCryptOpenStorageProvider...\n");

    /* Dynamically load ncrypt.dll to test */
    HMODULE hNcrypt = LoadLibraryW(L"ncrypt.dll");
    if (hNcrypt) {
        typedef SECURITY_STATUS (WINAPI *PFN_NCryptOpenStorageProvider)(
            NCRYPT_PROV_HANDLE *phProvider, LPCWSTR pszProviderName, DWORD dwFlags);
        typedef SECURITY_STATUS (WINAPI *PFN_NCryptFreeObject)(NCRYPT_PROV_HANDLE hObject);

        PFN_NCryptOpenStorageProvider pfnOpen = (PFN_NCryptOpenStorageProvider)
            GetProcAddress(hNcrypt, "NCryptOpenStorageProvider");
        PFN_NCryptFreeObject pfnFree = (PFN_NCryptFreeObject)
            GetProcAddress(hNcrypt, "NCryptFreeObject");

        if (pfnOpen && pfnFree) {
            NCRYPT_PROV_HANDLE hProv = 0;
            SECURITY_STATUS sec = pfnOpen(&hProv, KSP_NAME, 0);
            if (sec == 0) {
                printf("    [OK] NCryptOpenStorageProvider SUCCESS!\n");
                pfnFree(hProv);
            } else {
                printf("    [FAIL] NCryptOpenStorageProvider: 0x%08X\n", (unsigned int)sec);
                if (sec == (SECURITY_STATUS)0xC0000225) {
                    printf("    STATUS_NOT_FOUND - DLL may need to be re-signed or system restarted\n");
                }
            }
        }
        FreeLibrary(hNcrypt);
    }

    printf("\n=== Done ===\n");
    printf("If test passed, try: certutil -csp \"OpenCert Key Storage Provider\" -key\n");
    return 0;
}
