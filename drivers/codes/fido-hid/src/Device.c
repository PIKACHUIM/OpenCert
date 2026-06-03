/*
 * Device.c - OpenCert FIDO2 HID 虚拟设备
 *
 * 职责：
 *   1. 创建 WDF 设备对象
 *   2. 实现 IHidReportDescriptor COM 接口，向 mshidumdf.sys 提供 HID 报告描述符
 *   3. 处理电源状态转换
 *   4. 初始化 I/O 队列
 *
 * mshidumdf.sys 工作流程：
 *   1. mshidumdf 加载后，通过 WdfDeviceQueryInterface 查询本驱动的
 *      IHidReportDescriptor 接口
 *   2. 调用 GetReportDescriptor() 获取 HID 报告描述符
 *   3. 将描述符传递给 hidclass.sys
 *   4. hidclass.sys 解析 Usage Page 0xF1D0，识别为 FIDO2 设备
 *   5. Windows WebAuthn API 发现此设备
 */

#include "Driver.h"

/* 由 Driver.c 提供 */
extern void OpenCertHidTrace(const char* tag, NTSTATUS status);
#define TRACE(msg)        OpenCertHidTrace(msg, 0)
#define TRACE_S(msg, st)  OpenCertHidTrace(msg, (st))

/* ================================================================
 * IHidReportDescriptor 接口实现
 *
 * mshidumdf.sys 通过此接口获取 HID 报告描述符。
 * 接口 GUID：{F1CB2A8B-5C6A-4B8A-9B2E-3F4A5B6C7D8E}（自定义，与 mshidumdf 约定）
 * ================================================================ */

/* IHidReportDescriptor 接口 GUID（mshidumdf.h 中定义） */
/* 此处使用 UMDF 提供的 HID minidriver 接口 */

typedef struct _HID_REPORT_DESCRIPTOR_INTERFACE {
    /* 获取报告描述符长度 */
    USHORT (*GetReportDescriptorLength)(PVOID Context);
    /* 获取报告描述符内容 */
    NTSTATUS (*GetReportDescriptor)(
        PVOID   Context,
        PVOID   Buffer,
        ULONG   BufferLength,
        PULONG  BytesReturned
    );
} HID_REPORT_DESCRIPTOR_INTERFACE, *PHID_REPORT_DESCRIPTOR_INTERFACE;

/* ================================================================
 * DeviceCreate - 创建并初始化 WDF HID 设备
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
    devCtx->ChannelId   = 0;
    devCtx->Initialized = FALSE;
    devCtx->MsgPending  = FALSE;

    /* ---- 5. 初始化 I/O 队列 ---- */
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
    devCtx->Initialized = FALSE;
    devCtx->MsgPending  = FALSE;
    devCtx->ChannelId   = 0;

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
    devCtx->MsgPending = FALSE;

    return STATUS_SUCCESS;
}