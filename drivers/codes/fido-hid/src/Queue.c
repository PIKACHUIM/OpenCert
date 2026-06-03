/*
 * Queue.c - OpenCert FIDO2 HID I/O 队列
 *
 * 实现 CTAPHID（FIDO2 over HID）协议：
 *
 * HID 通信模型：
 *   - 每个 HID 报告固定 64 字节（无报告 ID）
 *   - 初始化包：[CID(4)][CMD|0x80(1)][BCNT_H(1)][BCNT_L(1)][DATA(57)]
 *   - 续传包：  [CID(4)][SEQ(1)][DATA(59)]
 *
 * 支持的 CTAPHID 命令：
 *   CTAPHID_CMD_INIT   (0x06) → 分配通道 ID
 *   CTAPHID_CMD_CBOR   (0x10) → CTAP2 CBOR 消息，转发给 Go 后端
 *   CTAPHID_CMD_PING   (0x01) → 回显
 *   CTAPHID_CMD_CANCEL (0x11) → 取消当前操作
 *   CTAPHID_CMD_MSG    (0x03) → CTAP1/U2F（返回不支持）
 *
 * HID IOCTL：
 *   IOCTL_HID_GET_DEVICE_DESCRIPTOR     → 返回 HID 设备描述符
 *   IOCTL_HID_GET_REPORT_DESCRIPTOR     → 返回报告描述符（Usage Page 0xF1D0）
 *   IOCTL_HID_GET_DEVICE_ATTRIBUTES     → 返回 VID/PID/版本
 *   IOCTL_HID_READ_REPORT               → 读取 HID 输入报告（挂起等待）
 *   IOCTL_HID_WRITE_REPORT              → 写入 HID 输出报告（处理 CTAPHID 命令）
 *   IOCTL_HID_GET_STRING                → 返回设备字符串
 *
 * 参考：
 *   FIDO CTAP2 over HID: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
 *   HID minidriver: https://docs.microsoft.com/windows-hardware/drivers/hid/
 */

#include "Driver.h"

/* 由 Driver.c 提供 */
extern void OpenCertHidTrace(const char* tag, NTSTATUS status);
#define TRACE(msg)        OpenCertHidTrace(msg, 0)
#define TRACE_S(msg, st)  OpenCertHidTrace(msg, (st))

/*
 * HID IOCTL 代码（来自 hidport.h，此处手动定义避免依赖 WDK hidport.h）
 * 这些是 hidclass.sys 发给 HID minidriver 的标准 IOCTL
 */
/*
 * HID minidriver IOCTL 代码（来自 WDK hidport.h）
 * FILE_DEVICE_KEYBOARD = 0x0000000b
 * 这些 IOCTL 由 mshidumdf.sys 转发给本 UMDF 驱动
 */
#ifndef IOCTL_HID_GET_DEVICE_DESCRIPTOR
#define IOCTL_HID_GET_DEVICE_DESCRIPTOR     CTL_CODE(FILE_DEVICE_KEYBOARD, 0x100, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_HID_GET_REPORT_DESCRIPTOR     CTL_CODE(FILE_DEVICE_KEYBOARD, 0x101, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_HID_GET_DEVICE_ATTRIBUTES     CTL_CODE(FILE_DEVICE_KEYBOARD, 0x102, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_HID_READ_REPORT               CTL_CODE(FILE_DEVICE_KEYBOARD, 0x103, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_HID_WRITE_REPORT              CTL_CODE(FILE_DEVICE_KEYBOARD, 0x104, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_HID_GET_STRING                CTL_CODE(FILE_DEVICE_KEYBOARD, 0x105, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_HID_ACTIVATE                  CTL_CODE(FILE_DEVICE_KEYBOARD, 0x107, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_HID_DEACTIVATE                CTL_CODE(FILE_DEVICE_KEYBOARD, 0x108, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_HID_GET_FEATURE               CTL_CODE(FILE_DEVICE_KEYBOARD, 0x100, METHOD_IN_DIRECT,  FILE_ANY_ACCESS)
#define IOCTL_HID_SET_FEATURE               CTL_CODE(FILE_DEVICE_KEYBOARD, 0x100, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#endif

/*
 * HID 设备描述符（9字节，标准 USB HID 描述符格式）
 */
#pragma pack(push, 1)
typedef struct _HID_DEVICE_DESCRIPTOR {
    BYTE  bLength;              /* 描述符长度 = 9 */
    BYTE  bDescriptorType;      /* 描述符类型 = 0x21 (HID) */
    USHORT bcdHID;              /* HID 规范版本 = 0x0111 (1.11) */
    BYTE  bCountryCode;         /* 国家代码 = 0 */
    BYTE  bNumDescriptors;      /* 下级描述符数量 = 1 */
    BYTE  bReportDescriptorType;/* 报告描述符类型 = 0x22 */
    USHORT wReportDescriptorLength; /* 报告描述符长度 */
} HID_DEVICE_DESCRIPTOR_T;

typedef struct _HID_DEVICE_ATTRIBUTES {
    ULONG  Size;                /* sizeof(HID_DEVICE_ATTRIBUTES) */
    USHORT VendorID;            /* VID */
    USHORT ProductID;           /* PID */
    USHORT VersionNumber;       /* 版本号 */
} HID_DEVICE_ATTRIBUTES_T;
#pragma pack(pop)

/* 虚拟设备 VID/PID（使用 FIDO Alliance 测试 VID） */
#define FIDO_VID    0x1050u  /* Yubico VID（测试用，生产需申请） */
#define FIDO_PID    0x0407u  /* YubiKey 5 NFC PID（测试用） */
#define FIDO_VER    0x0100u  /* 版本 1.0 */

/* ================================================================
 * QueueInitialize - 创建 I/O 队列
 * ================================================================ */
NTSTATUS
QueueInitialize(
    _In_ WDFDEVICE Device
)
{
    NTSTATUS            status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE            queue;
    WDF_IO_QUEUE_CONFIG readQueueConfig;
    WDFQUEUE            readQueue;
    PDEVICE_CONTEXT     devCtx;

    devCtx = GetDeviceContext(Device);

    /* ---- 默认队列：处理 IOCTL 和 Write ---- */
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchSequential
    );
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;
    queueConfig.EvtIoWrite         = EvtIoWrite;

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

    /* ---- 读队列：手动分发，挂起 Read 请求直到有数据 ---- */
    WDF_IO_QUEUE_CONFIG_INIT(
        &readQueueConfig,
        WdfIoQueueDispatchManual
    );

    status = WdfIoQueueCreate(
        Device,
        &readQueueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &readQueue
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }
    devCtx->ReadQueue = readQueue;

    /* 将 Read 请求转发到手动队列 */
    status = WdfDeviceConfigureRequestDispatching(
        Device,
        readQueue,
        WdfRequestTypeRead
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

/* ================================================================
 * 辅助：完成请求
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
 * 辅助：构造 CTAPHID 初始化包并发送给挂起的 Read 请求
 *
 * 初始化包格式（64字节）：
 *   [CID(4)][CMD|0x80(1)][BCNT_H(1)][BCNT_L(1)][DATA(57)]
 * ================================================================ */
static NTSTATUS
SendHidReport(
    _In_ PDEVICE_CONTEXT DevCtx,
    _In_ ULONG           Cid,
    _In_ BYTE            Cmd,
    _In_ const BYTE     *Data,
    _In_ ULONG           DataLen
)
{
    WDFREQUEST  pendingRequest;
    NTSTATUS    status;
    PVOID       outBuf = NULL;
    size_t      outLen = 0;
    BYTE        packet[CTAPHID_PACKET_SIZE];
    ULONG       offset = 0;
    BYTE        seq    = 0;
    ULONG       chunkSize;

    /* 取出一个挂起的 Read 请求 */
    status = WdfIoQueueRetrieveNextRequest(DevCtx->ReadQueue, &pendingRequest);
    if (!NT_SUCCESS(status)) {
        /* 没有挂起的读请求，丢弃（调用方应重试或缓存） */
        return STATUS_PENDING;
    }

    status = WdfRequestRetrieveOutputBuffer(pendingRequest, CTAPHID_PACKET_SIZE, &outBuf, &outLen);
    if (!NT_SUCCESS(status) || outLen < CTAPHID_PACKET_SIZE) {
        CompleteRequest(pendingRequest, STATUS_BUFFER_TOO_SMALL, 0);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* ---- 构造初始化包 ---- */
    RtlZeroMemory(packet, sizeof(packet));

    /* CID（大端序） */
    packet[0] = (BYTE)((Cid >> 24) & 0xFF);
    packet[1] = (BYTE)((Cid >> 16) & 0xFF);
    packet[2] = (BYTE)((Cid >>  8) & 0xFF);
    packet[3] = (BYTE)( Cid        & 0xFF);

    /* CMD | 0x80 */
    packet[4] = Cmd | CTAPHID_INIT_FLAG;

    /* BCNT（大端序） */
    packet[5] = (BYTE)((DataLen >> 8) & 0xFF);
    packet[6] = (BYTE)( DataLen       & 0xFF);

    /* 数据（最多 57 字节） */
    chunkSize = DataLen < 57u ? DataLen : 57u;
    if (chunkSize > 0 && Data) {
        RtlCopyMemory(packet + 7, Data, chunkSize);
    }
    offset = chunkSize;

    RtlCopyMemory(outBuf, packet, CTAPHID_PACKET_SIZE);
    CompleteRequest(pendingRequest, STATUS_SUCCESS, CTAPHID_PACKET_SIZE);

    /* ---- 续传包（如果数据超过 57 字节） ---- */
    while (offset < DataLen) {
        status = WdfIoQueueRetrieveNextRequest(DevCtx->ReadQueue, &pendingRequest);
        if (!NT_SUCCESS(status)) {
            break; /* 没有更多挂起请求，剩余数据丢弃 */
        }

        status = WdfRequestRetrieveOutputBuffer(pendingRequest, CTAPHID_PACKET_SIZE, &outBuf, &outLen);
        if (!NT_SUCCESS(status)) {
            CompleteRequest(pendingRequest, STATUS_BUFFER_TOO_SMALL, 0);
            break;
        }

        RtlZeroMemory(packet, sizeof(packet));
        packet[0] = (BYTE)((Cid >> 24) & 0xFF);
        packet[1] = (BYTE)((Cid >> 16) & 0xFF);
        packet[2] = (BYTE)((Cid >>  8) & 0xFF);
        packet[3] = (BYTE)( Cid        & 0xFF);
        packet[4] = seq++;  /* 序列号（无 0x80 标志） */

        chunkSize = (DataLen - offset) < 59u ? (DataLen - offset) : 59u;
        RtlCopyMemory(packet + 5, Data + offset, chunkSize);
        offset += chunkSize;

        RtlCopyMemory(outBuf, packet, CTAPHID_PACKET_SIZE);
        CompleteRequest(pendingRequest, STATUS_SUCCESS, CTAPHID_PACKET_SIZE);
    }

    return STATUS_SUCCESS;
}

/* ================================================================
 * 处理 CTAPHID_CMD_INIT（0x06）
 *
 * 客户端发送 8 字节 nonce，服务端分配通道 ID 并返回：
 *   [NONCE(8)][CID(4)][CTAPHID_PROTOCOL(1)][MAJOR(1)][MINOR(1)][BUILD(1)][CAPS(1)]
 * ================================================================ */
static NTSTATUS
HandleCtapHidInit(
    _In_ PDEVICE_CONTEXT DevCtx,
    _In_ ULONG           Cid,
    _In_ const BYTE     *Data,
    _In_ ULONG           DataLen
)
{
    BYTE    resp[17];
    ULONG   newCid;

    if (DataLen < 8) {
        BYTE errResp[1] = { CTAPHID_ERR_INVALID_LEN };
        SendHidReport(DevCtx, Cid, CTAPHID_CMD_ERROR, errResp, 1);
        return STATUS_SUCCESS;
    }

    /* 分配新通道 ID（简单递增，避免 0 和广播 ID） */
    DevCtx->ChannelId++;
    if (DevCtx->ChannelId == 0 || DevCtx->ChannelId == CTAPHID_BROADCAST_CID) {
        DevCtx->ChannelId = 1;
    }
    newCid = DevCtx->ChannelId;
    DevCtx->Initialized = TRUE;

    /* 构造响应 */
    RtlCopyMemory(resp, Data, 8);           /* nonce 回显 */
    resp[8]  = (BYTE)((newCid >> 24) & 0xFF);
    resp[9]  = (BYTE)((newCid >> 16) & 0xFF);
    resp[10] = (BYTE)((newCid >>  8) & 0xFF);
    resp[11] = (BYTE)( newCid        & 0xFF);
    resp[12] = 2;   /* CTAPHID_PROTOCOL_VERSION = 2 */
    resp[13] = 1;   /* MAJOR */
    resp[14] = 0;   /* MINOR */
    resp[15] = 0;   /* BUILD */
    resp[16] = 0x04; /* CAPS: CBOR=0x04 */

    return SendHidReport(DevCtx, Cid, CTAPHID_CMD_INIT, resp, sizeof(resp));
}

/* ================================================================
 * 处理 CTAPHID_CMD_CBOR（0x10）
 *
 * 将 CTAP2 CBOR 数据通过 IPC 转发给 Go 后端，
 * 接收响应后封装为 CTAPHID 响应包。
 * ================================================================ */
static NTSTATUS
HandleCtapHidCbor(
    _In_ PDEVICE_CONTEXT DevCtx,
    _In_ ULONG           Cid,
    _In_ const BYTE     *Data,
    _In_ ULONG           DataLen
)
{
    NTSTATUS    status;
    BYTE        ctapCmd;
    ULONG       cmdCode;
    char        reqJson[JSON_BUF_MAX];
    char        respJson[JSON_BUF_MAX];
    ULONG       ipcStatus = 0;

    /* Base64 编解码辅助（内联实现，避免依赖外部文件） */
    static const char B64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char    b64In[IPC_BUF_MAX];
    ULONG   b64InLen = 0;
    BYTE    respCbor[CTAP_RESP_MAX];
    ULONG   respCborLen = 0;

    /* CTAPHID 响应缓冲区：[CTAP2状态码(1)][CBOR数据] */
    BYTE    hidResp[CTAP_RESP_MAX + 1];
    ULONG   hidRespLen;

    if (DataLen < 1) {
        BYTE errResp[1] = { CTAPHID_ERR_INVALID_LEN };
        return SendHidReport(DevCtx, Cid, CTAPHID_CMD_ERROR, errResp, 1);
    }

    ctapCmd = Data[0];

    /* 根据 CTAP2 命令码选择 IPC 命令 */
    switch (ctapCmd) {
    case CTAP2_CMD_GET_INFO:
        cmdCode = CMD_FIDO_GET_INFO;
        break;
    case CTAP2_CMD_MAKE_CREDENTIAL:
        cmdCode = CMD_FIDO_MAKE_CREDENTIAL;
        break;
    case CTAP2_CMD_GET_ASSERTION:
        cmdCode = CMD_FIDO_GET_ASSERTION;
        break;
    case CTAP2_CMD_CLIENT_PIN:
        /* PIN 管理暂不实现，返回 CTAP2_ERR_PIN_NOT_SET (0x35) */
        hidResp[0] = 0x35;
        return SendHidReport(DevCtx, Cid, CTAPHID_CMD_CBOR, hidResp, 1);
    case CTAP2_CMD_RESET:
        /* Reset 暂不实现，返回 CTAP2_ERR_NOT_ALLOWED (0x30) */
        hidResp[0] = 0x30;
        return SendHidReport(DevCtx, Cid, CTAPHID_CMD_CBOR, hidResp, 1);
    default:
        hidResp[0] = CTAP1_ERR_INVALID_COMMAND;
        return SendHidReport(DevCtx, Cid, CTAPHID_CMD_CBOR, hidResp, 1);
    }

    /* ---- Base64 编码 CBOR 数据（跳过第一个字节命令码） ---- */
    if (DataLen > 1) {
        const BYTE *src = Data + 1;
        ULONG       srcLen = DataLen - 1;
        ULONG       i, j = 0;
        for (i = 0; i + 2 < srcLen && j + 4 < sizeof(b64In); i += 3) {
            b64In[j++] = B64[(src[i] >> 2) & 0x3F];
            b64In[j++] = B64[((src[i] & 0x03) << 4) | ((src[i+1] >> 4) & 0x0F)];
            b64In[j++] = B64[((src[i+1] & 0x0F) << 2) | ((src[i+2] >> 6) & 0x03)];
            b64In[j++] = B64[src[i+2] & 0x3F];
        }
        if (i < srcLen && j + 4 < sizeof(b64In)) {
            b64In[j++] = B64[(src[i] >> 2) & 0x3F];
            if (i + 1 < srcLen) {
                b64In[j++] = B64[((src[i] & 0x03) << 4) | ((src[i+1] >> 4) & 0x0F)];
                b64In[j++] = B64[(src[i+1] & 0x0F) << 2];
            } else {
                b64In[j++] = B64[(src[i] & 0x03) << 4];
                b64In[j++] = '=';
            }
            b64In[j++] = '=';
        }
        b64In[j] = '\0';
        b64InLen = j;
    } else {
        b64In[0] = '\0';
        b64InLen = 0;
    }
    (void)b64InLen;

    /* ---- 构造请求 JSON ---- */
    _snprintf_s(reqJson, sizeof(reqJson), _TRUNCATE,
        "{\"cmd\":%u,\"cbor\":\"%s\"}",
        (unsigned)ctapCmd,
        b64In
    );

    /* ---- 调用 IPC ---- */
    status = IpcCall(cmdCode, reqJson, respJson, sizeof(respJson), &ipcStatus);

    if (!NT_SUCCESS(status)) {
        hidResp[0] = CTAP1_ERR_OTHER;
        return SendHidReport(DevCtx, Cid, CTAPHID_CMD_CBOR, hidResp, 1);
    }

    if (ipcStatus != 0) {
        hidResp[0] = (BYTE)(ipcStatus & 0xFF);
        return SendHidReport(DevCtx, Cid, CTAPHID_CMD_CBOR, hidResp, 1);
    }

    /* ---- 从响应 JSON 中提取 Base64 编码的 CBOR 数据 ---- */
    {
        static int decTable[256];
        static BOOLEAN decInit = FALSE;
        const char *p, *start, *end;
        char b64Out[IPC_BUF_MAX];
        ULONG b64OutLen;
        ULONG i, j = 0;

        if (!decInit) {
            int k;
            for (k = 0; k < 256; k++) decTable[k] = -1;
            for (k = 0; k < 64; k++)  decTable[(BYTE)B64[k]] = k;
            decTable['='] = 0;
            decInit = TRUE;
        }

        /* 查找 "cbor" 字段 */
        p = strstr(respJson, "\"cbor\"");
        if (p) {
            p += 6;
            while (*p == ' ' || *p == ':') p++;
            if (*p == '"') {
                p++;
                start = p;
                end = strchr(start, '"');
                if (end) {
                    b64OutLen = (ULONG)(end - start);
                    if (b64OutLen < sizeof(b64Out)) {
                        RtlCopyMemory(b64Out, start, b64OutLen);
                        b64Out[b64OutLen] = '\0';
                        /* Base64 解码 */
                        for (i = 0; i + 3 < b64OutLen && j < sizeof(respCbor); i += 4) {
                            int c0 = decTable[(BYTE)b64Out[i]];
                            int c1 = decTable[(BYTE)b64Out[i+1]];
                            int c2 = decTable[(BYTE)b64Out[i+2]];
                            int c3 = decTable[(BYTE)b64Out[i+3]];
                            if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) break;
                            if (j < sizeof(respCbor)) respCbor[j++] = (BYTE)((c0 << 2) | (c1 >> 4));
                            if (b64Out[i+2] != '=' && j < sizeof(respCbor)) respCbor[j++] = (BYTE)((c1 << 4) | (c2 >> 2));
                            if (b64Out[i+3] != '=' && j < sizeof(respCbor)) respCbor[j++] = (BYTE)((c2 << 6) | c3);
                        }
                        respCborLen = j;
                    }
                }
            }
        }
    }

    /* ---- 构造 CTAPHID CBOR 响应：[CTAP2_OK(1)][CBOR数据] ---- */
    hidResp[0] = CTAP2_OK;
    if (respCborLen > 0 && respCborLen < sizeof(hidResp) - 1) {
        RtlCopyMemory(hidResp + 1, respCbor, respCborLen);
    }
    hidRespLen = 1 + respCborLen;

    return SendHidReport(DevCtx, Cid, CTAPHID_CMD_CBOR, hidResp, hidRespLen);
}

/* ================================================================
 * 处理 Write 请求（客户端发送 HID 输出报告）
 *
 * 解析 CTAPHID 包，分发给对应处理函数。
 * ================================================================ */
VOID
EvtIoWrite(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     Length
)
{
    PDEVICE_CONTEXT devCtx;
    WDFDEVICE       device;
    NTSTATUS        status;
    PVOID           inBuf = NULL;
    size_t          inLen = 0;
    const BYTE     *pkt;
    ULONG           cid;
    BYTE            cmdByte;
    BYTE            cmd;
    BOOLEAN         isInit;
    ULONG           bcnt;
    const BYTE     *data;
    ULONG           dataLen;

    UNREFERENCED_PARAMETER(Length);

    device = WdfIoQueueGetDevice(Queue);
    devCtx = GetDeviceContext(device);

    status = WdfRequestRetrieveInputBuffer(Request, CTAPHID_PACKET_SIZE, &inBuf, &inLen);
    if (!NT_SUCCESS(status) || inLen < CTAPHID_PACKET_SIZE) {
        CompleteRequest(Request, STATUS_INVALID_PARAMETER, 0);
        return;
    }

    pkt = (const BYTE *)inBuf;

    /* 解析 CID（大端序） */
    cid = ((ULONG)pkt[0] << 24)
        | ((ULONG)pkt[1] << 16)
        | ((ULONG)pkt[2] <<  8)
        |  (ULONG)pkt[3];

    cmdByte = pkt[4];
    isInit  = (cmdByte & CTAPHID_INIT_FLAG) != 0;
    cmd     = cmdByte & ~CTAPHID_INIT_FLAG;

    if (isInit) {
        /* 初始化包 */
        bcnt    = ((ULONG)pkt[5] << 8) | pkt[6];
        data    = pkt + 7;
        dataLen = (bcnt < 57u) ? bcnt : 57u;

        /* 简单处理：只支持单包消息（不做分片重组） */
        switch (cmd) {
        case CTAPHID_CMD_INIT:
            HandleCtapHidInit(devCtx, cid, data, dataLen);
            break;
        case CTAPHID_CMD_CBOR:
            HandleCtapHidCbor(devCtx, cid, data, dataLen);
            break;
        case CTAPHID_CMD_PING: {
            /* Ping：原样回显 */
            BYTE pingResp[57];
            ULONG pingLen = dataLen < sizeof(pingResp) ? dataLen : sizeof(pingResp);
            RtlCopyMemory(pingResp, data, pingLen);
            SendHidReport(devCtx, cid, CTAPHID_CMD_PING, pingResp, pingLen);
            break;
        }
        case CTAPHID_CMD_CANCEL:
            /* 取消：直接返回 OK（无正在进行的操作） */
            break;
        case CTAPHID_CMD_MSG:
            /* CTAP1/U2F 不支持 */
            {
                BYTE errResp[1] = { CTAPHID_ERR_INVALID_CMD };
                SendHidReport(devCtx, cid, CTAPHID_CMD_ERROR, errResp, 1);
            }
            break;
        default: {
            BYTE errResp[1] = { CTAPHID_ERR_INVALID_CMD };
            SendHidReport(devCtx, cid, CTAPHID_CMD_ERROR, errResp, 1);
            break;
        }
        }
    }
    /* 续传包暂不处理（单包消息已足够覆盖 CTAP2 基本操作） */

    CompleteRequest(Request, STATUS_SUCCESS, inLen);
}

/* ================================================================
 * EvtIoDeviceControl - IOCTL 分发
 *
 * 处理 hidclass.sys 发来的 HID minidriver IOCTL
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
    NTSTATUS        status;
    PVOID           outBuf = NULL;
    size_t          outLen = 0;

    UNREFERENCED_PARAMETER(InputBufferLength);

    device = WdfIoQueueGetDevice(Queue);
    devCtx = GetDeviceContext(device);
    (void)devCtx;

    switch (IoControlCode) {

    /* ---- HID 设备描述符 ---- */
    case IOCTL_HID_GET_DEVICE_DESCRIPTOR: {
        HID_DEVICE_DESCRIPTOR_T desc;
        if (OutputBufferLength < sizeof(desc)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            break;
        }
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(desc), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) {
            CompleteRequest(Request, status, 0);
            break;
        }
        desc.bLength                  = sizeof(desc);
        desc.bDescriptorType          = 0x21; /* HID */
        desc.bcdHID                   = 0x0111;
        desc.bCountryCode             = 0;
        desc.bNumDescriptors          = 1;
        desc.bReportDescriptorType    = 0x22; /* Report */
        desc.wReportDescriptorLength  = HID_REPORT_DESCRIPTOR_LEN;
        RtlCopyMemory(outBuf, &desc, sizeof(desc));
        CompleteRequest(Request, STATUS_SUCCESS, sizeof(desc));
        break;
    }

    /* ---- HID 报告描述符（Usage Page 0xF1D0） ---- */
    case IOCTL_HID_GET_REPORT_DESCRIPTOR: {
        if (OutputBufferLength < HID_REPORT_DESCRIPTOR_LEN) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            break;
        }
        status = WdfRequestRetrieveOutputBuffer(Request, HID_REPORT_DESCRIPTOR_LEN, &outBuf, &outLen);
        if (!NT_SUCCESS(status)) {
            CompleteRequest(Request, status, 0);
            break;
        }
        RtlCopyMemory(outBuf, HID_REPORT_DESCRIPTOR, HID_REPORT_DESCRIPTOR_LEN);
        CompleteRequest(Request, STATUS_SUCCESS, HID_REPORT_DESCRIPTOR_LEN);
        break;
    }

    /* ---- HID 设备属性（VID/PID/版本） ---- */
    case IOCTL_HID_GET_DEVICE_ATTRIBUTES: {
        HID_DEVICE_ATTRIBUTES_T attrs;
        if (OutputBufferLength < sizeof(attrs)) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            break;
        }
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(attrs), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) {
            CompleteRequest(Request, status, 0);
            break;
        }
        attrs.Size          = sizeof(attrs);
        attrs.VendorID      = FIDO_VID;
        attrs.ProductID     = FIDO_PID;
        attrs.VersionNumber = FIDO_VER;
        RtlCopyMemory(outBuf, &attrs, sizeof(attrs));
        CompleteRequest(Request, STATUS_SUCCESS, sizeof(attrs));
        break;
    }

    /* ---- HID 字符串（设备名称等） ---- */
    case IOCTL_HID_GET_STRING: {
        /* 返回设备名称字符串 */
        static const WCHAR devName[] = L"OpenCert FIDO2 Authenticator";
        ULONG nameBytes = sizeof(devName);
        if (OutputBufferLength < nameBytes) {
            CompleteRequest(Request, STATUS_BUFFER_TOO_SMALL, 0);
            break;
        }
        status = WdfRequestRetrieveOutputBuffer(Request, nameBytes, &outBuf, &outLen);
        if (!NT_SUCCESS(status)) {
            CompleteRequest(Request, status, 0);
            break;
        }
        RtlCopyMemory(outBuf, devName, nameBytes);
        CompleteRequest(Request, STATUS_SUCCESS, nameBytes);
        break;
    }

    /* ---- 激活/停用（直接成功） ---- */
    case IOCTL_HID_ACTIVATE:
    case IOCTL_HID_DEACTIVATE:
        CompleteRequest(Request, STATUS_SUCCESS, 0);
        break;

    default:
        CompleteRequest(Request, STATUS_INVALID_DEVICE_REQUEST, 0);
        break;
    }
}

/* ================================================================
 * EvtIoRead - 读请求（由手动队列转发过来的不会到这里）
 * 此函数保留为空，实际读请求由 ReadQueue 挂起等待 SendHidReport 完成
 * ================================================================ */
VOID
EvtIoRead(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     Length
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Length);

    /* 读请求应该已被路由到 ReadQueue（手动队列），不应到达这里 */
    /* 如果到达，挂起等待 */
    WdfRequestMarkCancelable(Request, NULL);
    /* 不完成请求，让它挂起 */
    (void)Request;
}
