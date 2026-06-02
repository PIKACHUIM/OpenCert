/*
 * Queue.c - OpenCert FIDO2 UMDF I/O 队列
 *
 * 处理 Windows PC/SC 框架发来的 SmartCardReader IOCTL 请求：
 *
 *   IOCTL_SMARTCARD_GET_ATTRIBUTE  → 返回读卡器属性（名称、ATR等）
 *   IOCTL_SMARTCARD_SET_ATTRIBUTE  → 忽略（虚拟设备）
 *   IOCTL_SMARTCARD_GET_STATE      → 返回卡片状态（SCARD_PRESENT）
 *   IOCTL_SMARTCARD_POWER          → 模拟上电/下电/复位
 *   IOCTL_SMARTCARD_SET_PROTOCOL   → 协商协议（T=1）
 *   IOCTL_SMARTCARD_TRANSMIT       → 转发 APDU 给 Ccid.c 处理
 *   IOCTL_SMARTCARD_IS_ABSENT      → 返回 STATUS_NO_MEDIA（卡始终在位）
 *   IOCTL_SMARTCARD_IS_PRESENT     → 返回 STATUS_SUCCESS
 *
 * 参考：
 *   https://docs.microsoft.com/windows-hardware/drivers/smartcard/smart-card-driver-library
 *   winsmcrd.h (Windows SDK)
 */

#include "Driver.h"

/* ================================================================
 * QueueInitialize - 创建默认 I/O 队列
 * ================================================================ */
NTSTATUS
QueueInitialize(
    _In_ WDFDEVICE Device
)
{
    NTSTATUS            status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE            queue;
    PDEVICE_CONTEXT     devCtx;

    devCtx = GetDeviceContext(Device);

    /* 串行队列：每次只处理一个请求，保证 APDU 顺序 */
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchSequential
    );

    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(
        Device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    devCtx->IoQueue = queue;
    return STATUS_SUCCESS;
}

/* ================================================================
 * 辅助：从 WDF 请求中读取输入缓冲区
 * ================================================================ */
static NTSTATUS
GetInputBuffer(
    _In_  WDFREQUEST Request,
    _Out_ PVOID     *Buffer,
    _Out_ size_t    *Length
)
{
    return WdfRequestRetrieveInputBuffer(Request, 0, Buffer, Length);
}

/* ================================================================
 * 辅助：从 WDF 请求中获取输出缓冲区
 * ================================================================ */
static NTSTATUS
GetOutputBuffer(
    _In_  WDFREQUEST Request,
    _Out_ PVOID     *Buffer,
    _Out_ size_t    *Length
)
{
    return WdfRequestRetrieveOutputBuffer(Request, 0, Buffer, Length);
}

/* ================================================================
 * 辅助：完成请求并设置信息长度
 * ================================================================ */
static VOID
CompleteRequest(
    _In_ WDFREQUEST Request,
    _In_ NTSTATUS   Status,
    _In_ ULONG_PTR  Information
)
{
    WdfRequestSetInformation(Request, Information);
    WdfRequestComplete(Request, Status);
}

/* ================================================================
 * 处理 IOCTL_SMARTCARD_GET_ATTRIBUTE
 *
 * 读卡器属性查询，PC/SC 框架用于识别设备能力。
 * 关键属性：
 *   SCARD_ATTR_VENDOR_NAME        → "OpenCert"
 *   SCARD_ATTR_VENDOR_IFD_TYPE    → "FIDO2 Virtual Reader"
 *   SCARD_ATTR_DEVICE_UNIT        → 0
 *   SCARD_ATTR_ATR_STRING         → FIDO_ATR
 *   SCARD_ATTR_CURRENT_PROTOCOL_TYPE → SCARD_PROTOCOL_T1
 *   SCARD_ATTR_ICC_PRESENCE       → 1（卡在位）
 * ================================================================ */
static NTSTATUS
HandleGetAttribute(
    _In_ PDEVICE_CONTEXT DevCtx,
    _In_ WDFREQUEST      Request
)
{
    NTSTATUS    status;
    PVOID       inBuf  = NULL;
    PVOID       outBuf = NULL;
    size_t      inLen  = 0;
    size_t      outLen = 0;
    ULONG       attrTag;
    ULONG_PTR   written = 0;

    UNREFERENCED_PARAMETER(DevCtx);

    status = GetInputBuffer(Request, &inBuf, &inLen);
    if (!NT_SUCCESS(status) || inLen < sizeof(ULONG)) {
        CompleteRequest(Request, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    attrTag = *(ULONG *)inBuf;

    status = GetOutputBuffer(Request, &outBuf, &outLen);
    if (!NT_SUCCESS(status)) {
        CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outBuf, outLen);

    switch (attrTag) {

    case SCARD_ATTR_VENDOR_NAME: {
        /* "OpenCert" */
        static const char vendorName[] = "OpenCert";
        size_t nameLen = sizeof(vendorName);
        if (outLen < nameLen) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(outBuf, vendorName, nameLen);
        written = nameLen;
        break;
    }

    case SCARD_ATTR_VENDOR_IFD_TYPE: {
        /* "FIDO2 Virtual Reader" */
        static const char ifdType[] = "FIDO2 Virtual Reader";
        size_t typeLen = sizeof(ifdType);
        if (outLen < typeLen) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(outBuf, ifdType, typeLen);
        written = typeLen;
        break;
    }

    case SCARD_ATTR_DEVICE_UNIT: {
        if (outLen < sizeof(ULONG)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(ULONG *)outBuf = 0;
        written = sizeof(ULONG);
        break;
    }

    case SCARD_ATTR_ATR_STRING: {
        if (outLen < FIDO_ATR_LEN) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(outBuf, FIDO_ATR, FIDO_ATR_LEN);
        written = FIDO_ATR_LEN;
        break;
    }

    case SCARD_ATTR_CURRENT_PROTOCOL_TYPE: {
        if (outLen < sizeof(ULONG)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(ULONG *)outBuf = SCARD_PROTOCOL_T1;
        written = sizeof(ULONG);
        break;
    }

    case SCARD_ATTR_ICC_PRESENCE: {
        if (outLen < sizeof(UCHAR)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(UCHAR *)outBuf = 1; /* 卡在位 */
        written = sizeof(UCHAR);
        break;
    }

    case SCARD_ATTR_ICC_INTERFACE_STATUS: {
        if (outLen < sizeof(UCHAR)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(UCHAR *)outBuf = 1; /* 接口激活 */
        written = sizeof(UCHAR);
        break;
    }

    case SCARD_ATTR_CHANNEL_ID: {
        if (outLen < sizeof(ULONG)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        /* 虚拟设备：通道类型=0x20（软件），单元=0 */
        *(ULONG *)outBuf = 0x00000020;
        written = sizeof(ULONG);
        break;
    }

    case SCARD_ATTR_ASYNC_PROTOCOL_TYPES:
    case SCARD_ATTR_SYNC_PROTOCOL_TYPES: {
        if (outLen < sizeof(ULONG)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(ULONG *)outBuf = 0;
        written = sizeof(ULONG);
        break;
    }

    case SCARD_ATTR_DEFAULT_CLK:
    case SCARD_ATTR_MAX_CLK: {
        if (outLen < sizeof(ULONG)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(ULONG *)outBuf = 3580; /* 3.58 MHz（虚拟值） */
        written = sizeof(ULONG);
        break;
    }

    case SCARD_ATTR_DEFAULT_DATA_RATE:
    case SCARD_ATTR_MAX_DATA_RATE: {
        if (outLen < sizeof(ULONG)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(ULONG *)outBuf = 9600;
        written = sizeof(ULONG);
        break;
    }

    case SCARD_ATTR_MAX_IFSD: {
        if (outLen < sizeof(ULONG)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(ULONG *)outBuf = 254;
        written = sizeof(ULONG);
        break;
    }

    case SCARD_ATTR_POWER_MGMT_SUPPORT: {
        if (outLen < sizeof(ULONG)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        *(ULONG *)outBuf = 0; /* 不支持电源管理 */
        written = sizeof(ULONG);
        break;
    }

    default:
        /* 未知属性 */
        CompleteRequest(Request, STATUS_NOT_SUPPORTED, 0);
        return STATUS_NOT_SUPPORTED;
    }

    CompleteRequest(Request, STATUS_SUCCESS, written);
    return STATUS_SUCCESS;
}

/* ================================================================
 * 处理 IOCTL_SMARTCARD_GET_STATE
 *
 * 返回卡片当前状态：
 *   SCARD_UNKNOWN   = 0
 *   SCARD_ABSENT    = 1
 *   SCARD_PRESENT   = 2
 *   SCARD_SWALLOWED = 3
 *   SCARD_POWERED   = 4
 *   SCARD_NEGOTIABLE= 5
 *   SCARD_SPECIFIC  = 6
 * ================================================================ */
static NTSTATUS
HandleGetState(
    _In_ PDEVICE_CONTEXT DevCtx,
    _In_ WDFREQUEST      Request
)
{
    NTSTATUS    status;
    PVOID       outBuf = NULL;
    size_t      outLen = 0;

    status = GetOutputBuffer(Request, &outBuf, &outLen);
    if (!NT_SUCCESS(status) || outLen < sizeof(ULONG)) {
        CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 虚拟卡始终处于 SCARD_SPECIFIC（已协商协议）状态 */
    *(ULONG *)outBuf = DevCtx->CardPresent ? SCARD_SPECIFIC : SCARD_ABSENT;

    CompleteRequest(Request, STATUS_SUCCESS, sizeof(ULONG));
    return STATUS_SUCCESS;
}

/* ================================================================
 * 处理 IOCTL_SMARTCARD_POWER
 *
 * 模拟卡片上电/下电/复位操作，返回 ATR。
 * ================================================================ */
static NTSTATUS
HandlePower(
    _In_ PDEVICE_CONTEXT DevCtx,
    _In_ WDFREQUEST      Request
)
{
    NTSTATUS    status;
    PVOID       inBuf  = NULL;
    PVOID       outBuf = NULL;
    size_t      inLen  = 0;
    size_t      outLen = 0;
    ULONG       powerAction;

    status = GetInputBuffer(Request, &inBuf, &inLen);
    if (!NT_SUCCESS(status) || inLen < sizeof(ULONG)) {
        CompleteRequest(Request, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    powerAction = *(ULONG *)inBuf;

    switch (powerAction) {
    case SCARD_COLD_RESET:
    case SCARD_WARM_RESET:
    case SCARD_POWER_UP:
        /* 复位后清除 Applet 选择状态 */
        DevCtx->AppletSelected = FALSE;
        DevCtx->CardPresent    = TRUE;

        /* 返回 ATR */
        status = GetOutputBuffer(Request, &outBuf, &outLen);
        if (!NT_SUCCESS(status) || outLen < FIDO_ATR_LEN) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(outBuf, FIDO_ATR, FIDO_ATR_LEN);
        CompleteRequest(Request, STATUS_SUCCESS, FIDO_ATR_LEN);
        break;

    case SCARD_POWER_DOWN:
        DevCtx->AppletSelected = FALSE;
        DevCtx->CardPresent    = FALSE;
        CompleteRequest(Request, STATUS_SUCCESS, 0);
        break;

    default:
        CompleteRequest(Request, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/* ================================================================
 * 处理 IOCTL_SMARTCARD_SET_PROTOCOL
 *
 * 协商传输协议，虚拟设备只支持 T=1。
 * ================================================================ */
static NTSTATUS
HandleSetProtocol(
    _In_ PDEVICE_CONTEXT DevCtx,
    _In_ WDFREQUEST      Request
)
{
    NTSTATUS    status;
    PVOID       inBuf  = NULL;
    PVOID       outBuf = NULL;
    size_t      inLen  = 0;
    size_t      outLen = 0;
    ULONG       requestedProtocol;

    UNREFERENCED_PARAMETER(DevCtx);

    status = GetInputBuffer(Request, &inBuf, &inLen);
    if (!NT_SUCCESS(status) || inLen < sizeof(ULONG)) {
        CompleteRequest(Request, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    requestedProtocol = *(ULONG *)inBuf;

    /* 只支持 T=1 或 RAW */
    if (!(requestedProtocol & (SCARD_PROTOCOL_T1 | SCARD_PROTOCOL_RAW))) {
        CompleteRequest(Request, STATUS_NOT_SUPPORTED, 0);
        return STATUS_NOT_SUPPORTED;
    }

    /* 返回已协商的协议 */
    status = GetOutputBuffer(Request, &outBuf, &outLen);
    if (!NT_SUCCESS(status) || outLen < sizeof(ULONG)) {
        CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
        return STATUS_BUFFER_TOO_SMALL;
    }

    *(ULONG *)outBuf = SCARD_PROTOCOL_T1;
    CompleteRequest(Request, STATUS_SUCCESS, sizeof(ULONG));
    return STATUS_SUCCESS;
}

/* ================================================================
 * 处理 IOCTL_SMARTCARD_TRANSMIT
 *
 * 核心 APDU 传输：将 APDU 转发给 Ccid.c，
 * Ccid.c 再通过 IPC 调用 Go 后端处理 CTAP2 命令。
 *
 * 输入格式：SCARD_IO_REQUEST + APDU 数据
 * 输出格式：SCARD_IO_REQUEST + 响应 APDU
 * ================================================================ */
static NTSTATUS
HandleTransmit(
    _In_ PDEVICE_CONTEXT DevCtx,
    _In_ WDFREQUEST      Request
)
{
    NTSTATUS    status;
    PVOID       inBuf  = NULL;
    PVOID       outBuf = NULL;
    size_t      inLen  = 0;
    size_t      outLen = 0;

    /* APDU 缓冲区（栈上分配，最大 64KB） */
    BYTE        apduResp[APDU_RESP_MAX_LEN];
    ULONG       apduRespLen = sizeof(apduResp);

    const BYTE *apduSend;
    ULONG       apduSendLen;

    status = GetInputBuffer(Request, &inBuf, &inLen);
    if (!NT_SUCCESS(status) || inLen <= sizeof(SCARD_IO_REQUEST)) {
        CompleteRequest(Request, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    status = GetOutputBuffer(Request, &outBuf, &outLen);
    if (!NT_SUCCESS(status) || outLen <= sizeof(SCARD_IO_REQUEST)) {
        CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 跳过 SCARD_IO_REQUEST 头，获取实际 APDU 数据 */
    apduSend    = (const BYTE *)inBuf  + sizeof(SCARD_IO_REQUEST);
    apduSendLen = (ULONG)(inLen        - sizeof(SCARD_IO_REQUEST));

    /* 调用 CCID 处理层 */
    status = CcidHandleApdu(
        DevCtx,
        apduSend,
        apduSendLen,
        apduResp,
        &apduRespLen
    );

    if (!NT_SUCCESS(status)) {
        CompleteRequest(Request, status, 0);
        return status;
    }

    /* 检查输出缓冲区是否足够 */
    if (outLen < sizeof(SCARD_IO_REQUEST) + apduRespLen) {
        CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 写入响应头（SCARD_IO_REQUEST） */
    SCARD_IO_REQUEST *respHeader = (SCARD_IO_REQUEST *)outBuf;
    respHeader->dwProtocol  = SCARD_PROTOCOL_T1;
    respHeader->cbPciLength = sizeof(SCARD_IO_REQUEST);

    /* 写入响应 APDU */
    RtlCopyMemory(
        (BYTE *)outBuf + sizeof(SCARD_IO_REQUEST),
        apduResp,
        apduRespLen
    );

    CompleteRequest(
        Request,
        STATUS_SUCCESS,
        sizeof(SCARD_IO_REQUEST) + apduRespLen
    );
    return STATUS_SUCCESS;
}

/* ================================================================
 * EvtIoDeviceControl - IOCTL 分发入口
 * ================================================================ */
VOID
EvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
)
{
    PDEVICE_CONTEXT devCtx;
    WDFDEVICE       device;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    device = WdfIoQueueGetDevice(Queue);
    devCtx = GetDeviceContext(device);

    switch (IoControlCode) {

    case IOCTL_SMARTCARD_GET_ATTRIBUTE:
        HandleGetAttribute(devCtx, Request);
        break;

    case IOCTL_SMARTCARD_SET_ATTRIBUTE:
        /* 虚拟设备忽略属性设置 */
        CompleteRequest(Request, STATUS_SUCCESS, 0);
        break;

    case IOCTL_SMARTCARD_GET_STATE:
        HandleGetState(devCtx, Request);
        break;

    case IOCTL_SMARTCARD_POWER:
        HandlePower(devCtx, Request);
        break;

    case IOCTL_SMARTCARD_SET_PROTOCOL:
        HandleSetProtocol(devCtx, Request);
        break;

    case IOCTL_SMARTCARD_TRANSMIT:
        HandleTransmit(devCtx, Request);
        break;

    case IOCTL_SMARTCARD_IS_PRESENT:
        /* 虚拟卡始终在位 */
        CompleteRequest(
            Request,
            devCtx->CardPresent ? STATUS_SUCCESS : STATUS_NO_MEDIA,
            0
        );
        break;

    case IOCTL_SMARTCARD_IS_ABSENT:
        /* 虚拟卡始终在位，所以 IS_ABSENT 返回 STATUS_NO_MEDIA */
        CompleteRequest(
            Request,
            devCtx->CardPresent ? STATUS_NO_MEDIA : STATUS_SUCCESS,
            0
        );
        break;

    case IOCTL_SMARTCARD_EJECT:
    case IOCTL_SMARTCARD_SWALLOW:
        /* 虚拟设备不支持物理操作 */
        CompleteRequest(Request, STATUS_NOT_SUPPORTED, 0);
        break;

    default:
        /* 未知 IOCTL */
        CompleteRequest(Request, STATUS_INVALID_DEVICE_REQUEST, 0);
        break;
    }
}
