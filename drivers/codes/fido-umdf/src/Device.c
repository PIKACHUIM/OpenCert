/*
 * Device.c - OpenCert FIDO2 UMDF 虚拟 SmartCardReader 设备
 *
 * 职责：
 *   1. 创建 WDF 设备对象，注册 GUID_DEVINTERFACE_SMARTCARD_READER 接口
 *   2. 设置设备安全描述符（允许普通用户访问）
 *   3. 处理电源状态转换（D0Entry / D0Exit）
 *   4. 初始化 I/O 队列
 */

#include "Driver.h"

/* 由 Driver.c 提供 */
extern void OpenCertTrace(const char* tag, NTSTATUS status);
#define TRACE(msg)        OpenCertTrace(msg, 0)
#define TRACE_S(msg, st)  OpenCertTrace(msg, (st))

/* GUID 实例：{50DD5230-BA8A-11D1-BF5D-0000F805F530} */
const GUID GUID_DEVINTERFACE_SMARTCARD_READER = {
    0x50DD5230, 0xBA8A, 0x11D1,
    { 0xBF, 0x5D, 0x00, 0x00, 0xF8, 0x05, 0xF5, 0x30 }
};

/* ================================================================
 * DeviceCreate - 创建并初始化 WDF 设备
 * ================================================================ */
NTSTATUS
DeviceCreate(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS                    status;
    WDF_OBJECT_ATTRIBUTES       deviceAttributes;
    WDFDEVICE                   device;
    PDEVICE_CONTEXT             devCtx;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;

    UNREFERENCED_PARAMETER(Driver);

    TRACE("DeviceCreate: ENTER");

    /* ---- 1. 注册 PnP/Power 回调 ---- */
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDeviceD0Entry = DeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit  = DeviceD0Exit;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);
    TRACE("DeviceCreate: after SetPnpPowerEventCallbacks");

    /* ---- 2. 设置设备上下文 ---- */
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    /* ---- 3. 创建 WDF 设备对象 ---- */
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    TRACE_S("DeviceCreate: WdfDeviceCreate", status);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* ---- 4. 初始化设备上下文 ---- */
    devCtx = GetDeviceContext(device);
    RtlZeroMemory(devCtx, sizeof(DEVICE_CONTEXT));
    devCtx->Device      = device;
    devCtx->CardPresent = TRUE;
    devCtx->AppletSelected = FALSE;

    /* ---- 5. 注册 SmartCardReader 设备接口 ---- */
    status = WdfDeviceCreateDeviceInterface(
        device,
        &GUID_DEVINTERFACE_SMARTCARD_READER,
        NULL
    );
    TRACE_S("DeviceCreate: WdfDeviceCreateDeviceInterface", status);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* ---- 6. 初始化 I/O 队列 ---- */
    status = QueueInitialize(device);
    TRACE_S("DeviceCreate: QueueInitialize", status);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    TRACE("DeviceCreate: SUCCESS");
    return STATUS_SUCCESS;
}

/* ================================================================
 * DeviceD0Entry - 设备进入工作状态（D0）
 * ================================================================ */
NTSTATUS
DeviceD0Entry(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
    PDEVICE_CONTEXT devCtx;

    UNREFERENCED_PARAMETER(PreviousState);

    TRACE("DeviceD0Entry");

    devCtx = GetDeviceContext(Device);
    devCtx->CardPresent    = TRUE;
    devCtx->AppletSelected = FALSE;
    devCtx->PowerState     = 0;

    return STATUS_SUCCESS;
}

/* ================================================================
 * DeviceD0Exit - 设备离开工作状态
 * ================================================================ */
NTSTATUS
DeviceD0Exit(
    _In_ WDFDEVICE              Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
)
{
    PDEVICE_CONTEXT devCtx;

    UNREFERENCED_PARAMETER(TargetState);

    TRACE("DeviceD0Exit");

    devCtx = GetDeviceContext(Device);
    devCtx->AppletSelected = FALSE;

    return STATUS_SUCCESS;
}