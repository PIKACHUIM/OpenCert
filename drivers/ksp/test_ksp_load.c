/* test_ksp_load.c - 测试 KSP DLL 是否能正确加载和调用 */
#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>

/* 模拟 CNG 调用 GetKeyStorageInterface 的签名 */
typedef NTSTATUS (WINAPI *PFN_GetKeyStorageInterface)(
    LPCWSTR pszProviderName,
    void **ppFunctionTable,
    DWORD dwFlags
);

int main(void)
{
    printf("=== OpenCert KSP DLL Load Test ===\n\n");

    /* Step 1: 加载 DLL */
    printf("[1] Loading OpenCertKSP.dll...\n");
    HMODULE hDll = LoadLibraryW(L"C:\\WINDOWS\\System32\\OpenCertKSP.dll");
    if (!hDll) {
        printf("    [FAIL] LoadLibrary failed: 0x%08lX\n", GetLastError());
        return 1;
    }
    printf("    [OK] DLL loaded at 0x%p\n", hDll);

    /* Step 2: 获取导出函数 */
    printf("[2] Getting GetKeyStorageInterface...\n");
    PFN_GetKeyStorageInterface pfn = (PFN_GetKeyStorageInterface)
        GetProcAddress(hDll, "GetKeyStorageInterface");
    if (!pfn) {
        printf("    [FAIL] GetProcAddress failed: 0x%08lX\n", GetLastError());
        FreeLibrary(hDll);
        return 1;
    }
    printf("    [OK] Function at 0x%p\n", pfn);

    /* Step 3: 调用函数 */
    printf("[3] Calling GetKeyStorageInterface...\n");
    void *pTable = NULL;
    NTSTATUS status = pfn(L"OpenCert Key Storage Provider", &pTable, 0);
    printf("    Status: 0x%08lX\n", (unsigned long)status);
    if (status == 0) {
        printf("    [OK] Function table returned at 0x%p\n", pTable);
        /* 检查 Version 字段 */
        if (pTable) {
            USHORT *ver = (USHORT *)pTable;
            printf("    Version: %u.%u\n", ver[0], ver[1]);
        }
    } else {
        printf("    [FAIL] GetKeyStorageInterface returned error\n");
    }

    /* Step 4: 尝试通过 NCrypt API 打开 */
    printf("\n[4] Testing NCryptOpenStorageProvider...\n");
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS sec = NCryptOpenStorageProvider(&hProv,
        L"OpenCert Key Storage Provider", 0);
    printf("    Status: 0x%08lX\n", (unsigned long)sec);
    if (sec == 0) {
        printf("    [OK] Provider opened: 0x%p\n", (void*)(uintptr_t)hProv);
        NCryptFreeObject(hProv);
    } else {
        printf("    [FAIL] NCryptOpenStorageProvider failed\n");
    }

    FreeLibrary(hDll);
    printf("\n=== Done ===\n");
    return 0;
}
