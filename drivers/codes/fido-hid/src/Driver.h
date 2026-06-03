/*
 * Driver.h - OpenCert FIDO2 HID 虚拟设备驱动
 *
 * 架构：
 *   浏览器 → Windows WebAuthn API
 *          → Windows HID 驱动栈（hidclass.sys）
 *          → mshidumdf.sys（HID minidriver 适配层）
 *          → 本驱动（OpenCertFIDOHidDriver.dll，UMDF2）
 *          → Named Pipe IPC
 *          → OpenCert client-card（Go 后端）
 *          → 智能卡 / 本地存储
 *
 * 设备节点：ROOT\OPENCERTFIDOHID\0000
 * 设备类：HIDClass（{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}）
 * HID Usage Page：0xF1D0（FIDO Alliance）
 * HID Usage：0x0001（FIDO Authenticator）
 *
 * mshidumdf.sys 负责：
 *   - 向 hidclass.sys 提供 HID 报告描述符
 *   - 将 HID I/O 请求（读/写/IOCTL）转发给本 UMDF 驱动
 *   - 本驱动通过 IHidReportDescriptor COM 接口提供报告描述符
 */

#pragma once

/* ---- Windows / WDF 头文件 ---- */
#include <windows.h>
#include <wdf.h>
#include <stdint.h>
#include <strsafe.h>
#include <stdio.h>

/* ---- 驱动标识 ---- */
#define DRIVER_NAME         L"OpenCertFIDOHidDriver"
#define DEVICE_NAME         L"\\Device\\OpenCertFIDOHid"

/* 设备硬件 ID，与 INF 保持一致 */
#define HARDWARE_ID         L"ROOT\\OPENCERTFIDOHID"

/* ---- HID FIDO2 常量 ---- */

/*
 * HID Usage Page 0xF1D0 = FIDO Alliance
 * HID Usage      0x0001 = FIDO Authenticator
 *
 * Windows WebAuthn API 通过扫描 HID 设备的 Usage Page/Usage 来发现 FIDO2 认证器。
 * 只要 HID 报告描述符中声明了这两个值，WebAuthn API 就会将其识别为 FIDO2 设备。
 */
#define HID_USAGE_PAGE_FIDO     0xF1D0u
#define HID_USAGE_FIDO_AUTH     0x0001u

/*
 * CTAPHID 包大小：固定 64 字节（USB HID Full Speed）
 * 每个 HID 报告 = 1字节报告ID(0) + 64字节数据
 */
#define CTAPHID_PACKET_SIZE     64u
#define HID_REPORT_SIZE         (CTAPHID_PACKET_SIZE + 1u)  /* +1 for Report ID */

/*
 * CTAPHID 命令（高位=1 表示初始化包）
 */
#define CTAPHID_CMD_MSG         0x03u   /* CTAP1/U2F 消息 */
#define CTAPHID_CMD_CBOR        0x10u   /* CTAP2 CBOR 消息 */
#define CTAPHID_CMD_INIT        0x06u   /* 初始化通道 */
#define CTAPHID_CMD_PING        0x01u   /* Ping */
#define CTAPHID_CMD_CANCEL      0x11u   /* 取消 */
#define CTAPHID_CMD_ERROR       0x3Fu   /* 错误 */
#define CTAPHID_CMD_KEEPALIVE   0x3Bu   /* 保活 */

/* CTAPHID 初始化包标志（bit7=1） */
#define CTAPHID_INIT_FLAG       0x80u

/* CTAPHID 广播通道 ID */
#define CTAPHID_BROADCAST_CID   0xFFFFFFFFu

/* CTAPHID 错误码 */
#define CTAPHID_ERR_INVALID_CMD     0x01u
#define CTAPHID_ERR_INVALID_PAR     0x02u
#define CTAPHID_ERR_INVALID_LEN     0x03u
#define CTAPHID_ERR_INVALID_SEQ     0x04u
#define CTAPHID_ERR_MSG_TIMEOUT     0x05u
#define CTAPHID_ERR_CHANNEL_BUSY    0x06u
#define CTAPHID_ERR_LOCK_REQUIRED   0x0Au
#define CTAPHID_ERR_INVALID_CHANNEL 0x0Bu
#define CTAPHID_ERR_OTHER           0x7Fu

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

/* IPC Named Pipe 名称（与 Go 后端一致） */
#define IPC_PIPE_NAME       L"\\\\.\\pipe\\opencert-ipc"
#define IPC_PIPE_NAME_A     "\\\\.\\pipe\\opencert-ipc"

/* IPC 命令码（与 protocol.go 保持一致） */
#define CMD_FIDO_GET_INFO           0x0300u
#define CMD_FIDO_MAKE_CREDENTIAL    0x0301u
#define CMD_FIDO_GET_ASSERTION      0x0302u
#define CMD_FIDO_CANCEL             0x0303u

/* ---- 缓冲区大小 ---- */
#define IPC_BUF_MAX         65536u
#define JSON_BUF_MAX        32768u
#define CTAP_RESP_MAX       7609u   /* CTAPHID 最大消息长度 */

/*
 * HID 报告描述符（34字节）
 *
 * Usage Page (FIDO Alliance, 0xF1D0)
 * Usage (FIDO Authenticator, 0x01)
 * Collection (Application)
 *   Usage (Input Report Data, 0x20)
 *   Logical Minimum (0)
 *   Logical Maximum (255)
 *   Report Size (8)
 *   Report Count (64)
 *   Input (Data, Variable, Absolute)
 *   Usage (Output Report Data, 0x21)
 *   Logical Minimum (0)
 *   Logical Maximum (255)
 *   Report Size (8)
 *   Report Count (64)
 *   Output (Data, Variable, Absolute)
 * End Collection
 */
#define HID_REPORT_DESCRIPTOR_LEN   34u
static const BYTE HID_REPORT_DESCRIPTOR[HID_REPORT_DESCRIPTOR_LEN] = {
    0x06, 0xD0, 0xF1,   /* Usage Page (FIDO Alliance, 0xF1D0) */
    0x09, 0x01,         /* Usage (FIDO Authenticator) */
    0xA1, 0x01,         /* Collection (Application) */
    /* Input report: 64 bytes */
    0x09, 0x20,         /*   Usage (Input Report Data) */
    0x15, 0x00,         /*   Logical Minimum (0) */
    0x26, 0xFF, 0x00,   /*   Logical Maximum (255) */
    0x75, 0x08,         /*   Report Size (8 bits) */
    0x95, 0x40,         /*   Report Count (64) */
    0x81, 0x02,         /*   Input (Data, Variable, Absolute) */
    /* Output report: 64 bytes */
    0x09, 0x21,         /*   Usage (Output Report Data) */
    0x15, 0x00,         /*   Logical Minimum (0) */
    0x26, 0xFF, 0x00,   /*   Logical Maximum (255) */
    0x75, 0x08,         /*   Report Size (8 bits) */
    0x95, 0x40,         /*   Report Count (64) */
    0x91, 0x02,         /*   Output (Data, Variable, Absolute) */
    0xC0                /* End Collection */
};

/* ---- 设备上下文 ---- */
typedef struct _DEVICE_CONTEXT {
    WDFDEVICE       Device;         /* WDF 设备对象 */
    WDFQUEUE        IoQueue;        /* 默认 I/O 队列 */
    WDFQUEUE        ReadQueue;      /* 读请求挂起队列（手动分发） */
    ULONG           ChannelId;      /* 当前 CTAPHID 通道 ID */
    BOOLEAN         Initialized;    /* 通道是否已初始化 */
    /* 分片重组缓冲区 */
    BYTE            MsgBuf[CTAP_RESP_MAX];
    ULONG           MsgLen;         /* 期望总长度 */
    ULONG           MsgReceived;    /* 已接收字节数 */
    BYTE            MsgCmd;         /* 当前消息命令码 */
    ULONG           MsgCid;         /* 当前消息通道 ID */
    BYTE            SeqExpected;    /* 期望的下一个序列号 */
    BOOLEAN         MsgPending;     /* 是否有消息正在接收 */
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

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
EVT_WDF_IO_QUEUE_IO_READ        EvtIoRead;
EVT_WDF_IO_QUEUE_IO_WRITE       EvtIoWrite;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

/* Ipc.c */
NTSTATUS IpcCall(
    ULONG       CmdCode,
    const char *ReqJson,
    char       *RespBuf,
    ULONG       RespBufLen,
    ULONG      *OutStatus
);
