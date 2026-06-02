/*
 * Driver.h - OpenCert FIDO2 UMDF 虚拟 CCID 驱动
 *
 * 架构：
 *   浏览器 → Windows WebAuthn API
 *          → Windows CCID 驱动栈（wudfrd.sys）
 *          → 本驱动（OpenCertFIDODriver.dll，UMDF2）
 *          → Named Pipe IPC
 *          → OpenCert client-card（Go 后端）
 *          → 智能卡 / 本地存储
 *
 * 设备节点：ROOT\OPENCERTFIDO\0000
 * 设备接口：GUID_DEVINTERFACE_SMARTCARD_READER
 *
 * 参考：
 *   UMDF2: https://docs.microsoft.com/windows-hardware/drivers/wdf/
 *   CCID:  https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf
 *   FIDO2 CTAP2: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
 */

#pragma once

/* ---- Windows / WDF 头文件 ---- */
#include <windows.h>
#include <wdf.h>
#include <devguid.h>

/* 在 include winsmcrd.h 之前 undef INITGUID，
 * 使 DEFINE_GUID 退化为 extern 声明（实际定义在 Device.c 中） */
#ifdef INITGUID
#undef INITGUID
#endif
#include <winsmcrd.h>   /* SmartCard IOCTL 定义 */

/* GUID_DEVINTERFACE_SMARTCARD_READER 在 Device.c 中定义，此处声明 */
extern const GUID GUID_DEVINTERFACE_SMARTCARD_READER;
#include <stdint.h>
#include <strsafe.h>

/* ---- 补充 winsmcrd.h 中被注释掉或来自 km smclib.h 的常量 ---- */
/* 协议类型属性（winsmcrd.h 中被注释，此处补充） */
#ifndef SCARD_ATTR_ASYNC_PROTOCOL_TYPES
#define SCARD_ATTR_ASYNC_PROTOCOL_TYPES  SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0120)
#endif
#ifndef SCARD_ATTR_SYNC_PROTOCOL_TYPES
#define SCARD_ATTR_SYNC_PROTOCOL_TYPES   SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0126)
#endif

/* SCARD_POWER_UP 来自 km smclib.h，winsmcrd.h 中无此定义 */
#ifndef SCARD_POWER_UP
#define SCARD_POWER_UP  3
#endif

/* ---- 驱动标识 ---- */
#define DRIVER_NAME         L"OpenCertFIDODriver"
#define DEVICE_NAME         L"\\Device\\OpenCertFIDO"
#define DEVICE_SYMLINK      L"\\DosDevices\\OpenCertFIDO"

/* 设备硬件 ID，与 INF 保持一致 */
#define HARDWARE_ID         L"ROOT\\OPENCERTFIDO"

/* 读卡器名称（Windows PC/SC 框架显示的名称） */
#define READER_NAME         "OpenCert FIDO2 Virtual Reader 0"
#define READER_NAME_W       L"OpenCert FIDO2 Virtual Reader 0"

/* ---- FIDO2 / CCID 常量 ---- */

/* FIDO2 Applet AID: A0 00 00 06 47 2F 00 01 */
#define FIDO_AID_LEN        8
static const BYTE FIDO_AID[FIDO_AID_LEN] = {
    0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
};

/* ATR（Answer To Reset）：虚拟卡的 ATR，用于 PC/SC 识别 */
#define FIDO_ATR_LEN        17
static const BYTE FIDO_ATR[FIDO_ATR_LEN] = {
    0x3B, 0xF7, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE,
    0x45, 0x4F, 0x70, 0x65, 0x6E, 0x43, 0x65, 0x72,
    0x74  /* "OpenCert" */
};

/* CTAP2 命令码 */
#define CTAP2_CMD_MAKE_CREDENTIAL   0x01u
#define CTAP2_CMD_GET_ASSERTION     0x02u
#define CTAP2_CMD_GET_INFO          0x04u
#define CTAP2_CMD_CLIENT_PIN        0x06u
#define CTAP2_CMD_RESET             0x07u

/* CTAP2 状态码 */
#define CTAP2_OK                    0x00u
#define CTAP1_ERR_INVALID_COMMAND   0x01u
#define CTAP2_ERR_NOT_ALLOWED       0x30u
#define CTAP1_ERR_OTHER             0x7Fu

/* APDU 指令 */
#define APDU_CLA_ISO                0x00u
#define APDU_CLA_FIDO               0x80u
#define APDU_INS_SELECT             0xA4u
#define APDU_INS_FIDO2              0x10u

/* APDU 状态字 */
#define APDU_SW_SUCCESS             0x9000u
#define APDU_SW_INS_NOT_SUPPORTED   0x6D00u
#define APDU_SW_UNKNOWN             0x6F00u
#define APDU_SW_WRONG_DATA          0x6A80u

/* IPC Named Pipe 名称（与 Go 后端一致） */
#define IPC_PIPE_NAME       L"\\\\.\\pipe\\opencert-ipc"
#define IPC_PIPE_NAME_A     "\\\\.\\pipe\\opencert-ipc"

/* IPC 命令码（与 protocol.go 保持一致） */
#define CMD_FIDO_GET_INFO           0x0300u
#define CMD_FIDO_MAKE_CREDENTIAL    0x0301u
#define CMD_FIDO_GET_ASSERTION      0x0302u
#define CMD_FIDO_CANCEL             0x0303u
#define CMD_FIDO_LOGIN              0x0304u

/* ---- 缓冲区大小 ---- */
#define APDU_MAX_LEN        65542u
#define APDU_RESP_MAX_LEN   65536u
#define IPC_BUF_MAX         65536u
#define JSON_BUF_MAX        32768u

/* ---- 设备上下文 ---- */
typedef struct _DEVICE_CONTEXT {
    WDFDEVICE       Device;         /* WDF 设备对象 */
    WDFQUEUE        IoQueue;        /* 默认 I/O 队列 */
    BOOLEAN         CardPresent;    /* 虚拟卡是否"插入" */
    BOOLEAN         AppletSelected; /* FIDO Applet 是否已 SELECT */
    ULONG           PowerState;     /* 设备电源状态 */
    /* 预留扩展字段（Q4:b） */
    PVOID           Reserved[4];
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

/* ---- 请求上下文（每个 IRP 附带的私有数据） ---- */
typedef struct _REQUEST_CONTEXT {
    ULONG   IoControlCode;  /* IOCTL 代码 */
    PVOID   Reserved;       /* 预留 */
} REQUEST_CONTEXT, *PREQUEST_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(REQUEST_CONTEXT, GetRequestContext)

/* ================================================================
 * 函数声明（跨文件）
 * ================================================================ */

/* Driver.c */
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD       EvtDriverDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP  EvtDriverContextCleanup;

/* Device.c */
NTSTATUS DeviceCreate(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit);
NTSTATUS DeviceD0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);
NTSTATUS DeviceD0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState);

/* Queue.c */
NTSTATUS QueueInitialize(WDFDEVICE Device);
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

/* Ipc.c */
NTSTATUS IpcCall(
    ULONG       CmdCode,
    const char *ReqJson,
    char       *RespBuf,
    ULONG       RespBufLen,
    ULONG      *OutStatus
);

/* Ccid.c */
NTSTATUS CcidHandleApdu(
    PDEVICE_CONTEXT DevCtx,
    const BYTE     *SendBuf,
    ULONG           SendLen,
    BYTE           *RecvBuf,
    ULONG          *RecvLen
);
