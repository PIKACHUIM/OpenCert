/*
 * Driver.c - OpenCert FIDO2 HID 驱动入口
 *
 * 实现 DriverEntry 和 EvtDriverDeviceAdd，
 * 向 WDF 框架注册驱动并创建虚拟 HID FIDO2 设备。
 *
 * 与 UMDF SmartCardReader 方案的区别：
 *   - 设备类：HIDClass（而非 SmartCardReader）
 *   - Windows WebAuthn API 通过 HID Usage Page 0xF1D0 直接识别
 *   - 无需 PC/SC 框架（SCardSvr），无 UMDF 1.x 兼容性问题
 */

#include "Driver.h"

/* 调试探针：同时写 OutputDebugStringA + 文件 */
static void DbgTrace(const char* tag, NTSTATUS status)
{
    char  buf[512];
    DWORD wrote = 0;
    HANDLE h;
    SYSTEMTIME st;

    GetLocalTime(&st);
    StringCchPrintfA(buf, sizeof(buf),
        "[%02d:%02d:%02d.%03d] [OPENCERTFIDOHID] %s status=0x%08X\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        tag, (unsigned)status);
    OutputDebugStringA(buf);

    h = CreateFileA("C:\\ProgramData\\opencertfidohid_trace.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        WriteFile(h, buf, (DWORD)strlen(buf), &wrote, NULL);
        CloseHandle(h);
    }
}

#define TRACE(msg)        DbgTrace(msg, 0)
#define TRACE_S(msg, st)  DbgTrace(msg, (st))

/* ================================================================
 * DriverEntry - 驱动程序入口点
 * ================================================================ */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    WDF_DRIVER_CONFIG   config;
    WDF_OBJECT_ATTRIBUTES attributes;
    NTSTATUS            status;

    TRACE("DriverEntry: ENTER");

    WDF_DRIVER_CONFIG_INIT(&config, EvtDriverDeviceAdd);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = EvtDriverContextCleanup;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        WDF_NO_HANDLE
    );

    TRACE_S("DriverEntry: WdfDriverCreate", status);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    TRACE("DriverEntry: SUCCESS");
    return STATUS_SUCCESS;
}

/* ================================================================
 * EvtDriverDeviceAdd - 设备添加回调
 * ================================================================ */
NTSTATUS
EvtDriverDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(Driver);

    TRACE("EvtDriverDeviceAdd: ENTER");

    status = DeviceCreate(Driver, DeviceInit);

    TRACE_S("EvtDriverDeviceAdd: DeviceCreate returned", status);
    return status;
}

/* ================================================================
 * EvtDriverContextCleanup - 驱动卸载清理
 * ================================================================ */
VOID
EvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    TRACE("EvtDriverContextCleanup");
}

/* 提供给其他文件使用的全局探针函数 */
void OpenCertHidTrace(const char* tag, NTSTATUS status) { DbgTrace(tag, status); }
