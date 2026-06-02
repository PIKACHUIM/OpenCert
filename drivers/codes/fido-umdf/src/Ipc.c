/*
 * Ipc.c - OpenCert FIDO2 UMDF 驱动 IPC 通信层
 *
 * 通过 Named Pipe 与 OpenCert client-card（Go 后端）通信。
 * 协议格式与现有 KSP/CSP 的 ipc_client.c 保持一致：
 *
 *   请求帧：[4字节命令码][4字节长度][JSON数据]
 *   响应帧：[4字节状态码][4字节长度][JSON数据]
 *
 * 注意：UMDF 驱动运行在用户态，可以直接使用 Win32 API 访问 Named Pipe。
 */

#include "Driver.h"

/* ================================================================
 * IpcCall - 发送 IPC 请求并接收响应
 *
 * 参数：
 *   CmdCode    - 命令码（CMD_FIDO_xxx）
 *   ReqJson    - 请求 JSON 字符串（UTF-8，以 \0 结尾）
 *   RespBuf    - 响应 JSON 缓冲区（调用方提供）
 *   RespBufLen - 响应缓冲区大小
 *   OutStatus  - [out] Go 后端返回的状态码（0=成功）
 *
 * 返回：
 *   STATUS_SUCCESS          - 成功
 *   STATUS_PIPE_NOT_AVAILABLE - Pipe 未就绪（后端未运行）
 *   STATUS_IO_TIMEOUT       - 超时
 *   STATUS_BUFFER_TOO_SMALL - 响应缓冲区不足
 * ================================================================ */
NTSTATUS
IpcCall(
    _In_  ULONG       CmdCode,
    _In_  const char *ReqJson,
    _Out_ char       *RespBuf,
    _In_  ULONG       RespBufLen,
    _Out_ ULONG      *OutStatus
)
{
    HANDLE  hPipe = INVALID_HANDLE_VALUE;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    DWORD   dwWritten = 0;
    DWORD   dwRead    = 0;
    BOOL    bOk;

    /* 请求帧缓冲区 */
    BYTE    sendBuf[IPC_BUF_MAX];
    ULONG   sendLen = 0;
    ULONG   jsonLen;

    /* 响应帧缓冲区 */
    BYTE    recvBuf[IPC_BUF_MAX];
    ULONG   recvStatus;
    ULONG   recvDataLen;

    *OutStatus = 0xFFFFFFFF;

    if (!ReqJson || !RespBuf || RespBufLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    jsonLen = (ULONG)strlen(ReqJson);
    if (jsonLen + 8 > sizeof(sendBuf)) {
        return STATUS_BUFFER_OVERFLOW;
    }

    /* ---- 构造请求帧 ---- */
    /* [4字节 LE 命令码] */
    sendBuf[0] = (BYTE)(CmdCode & 0xFF);
    sendBuf[1] = (BYTE)((CmdCode >> 8) & 0xFF);
    sendBuf[2] = (BYTE)((CmdCode >> 16) & 0xFF);
    sendBuf[3] = (BYTE)((CmdCode >> 24) & 0xFF);
    /* [4字节 LE JSON 长度] */
    sendBuf[4] = (BYTE)(jsonLen & 0xFF);
    sendBuf[5] = (BYTE)((jsonLen >> 8) & 0xFF);
    sendBuf[6] = (BYTE)((jsonLen >> 16) & 0xFF);
    sendBuf[7] = (BYTE)((jsonLen >> 24) & 0xFF);
    /* [JSON 数据] */
    RtlCopyMemory(sendBuf + 8, ReqJson, jsonLen);
    sendLen = 8 + jsonLen;

    /* ---- 连接 Named Pipe ---- */
    /* 等待 Pipe 就绪（最多 5 秒） */
    if (!WaitNamedPipeA(IPC_PIPE_NAME_A, 5000)) {
        return STATUS_PIPE_NOT_AVAILABLE;
    }

    hPipe = CreateFileA(
        IPC_PIPE_NAME_A,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        return STATUS_PIPE_NOT_AVAILABLE;
    }

    /* 设置管道为消息模式 */
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);

    /* ---- 发送请求 ---- */
    bOk = WriteFile(hPipe, sendBuf, sendLen, &dwWritten, NULL);
    if (!bOk || dwWritten != sendLen) {
        ntStatus = STATUS_PIPE_BROKEN;
        goto cleanup;
    }

    /* ---- 接收响应 ---- */
    bOk = ReadFile(hPipe, recvBuf, sizeof(recvBuf) - 1, &dwRead, NULL);
    if (!bOk || dwRead < 8) {
        ntStatus = STATUS_PIPE_BROKEN;
        goto cleanup;
    }

    /* ---- 解析响应帧 ---- */
    /* [4字节 LE 状态码] */
    recvStatus = (ULONG)recvBuf[0]
               | ((ULONG)recvBuf[1] << 8)
               | ((ULONG)recvBuf[2] << 16)
               | ((ULONG)recvBuf[3] << 24);

    /* [4字节 LE 数据长度] */
    recvDataLen = (ULONG)recvBuf[4]
                | ((ULONG)recvBuf[5] << 8)
                | ((ULONG)recvBuf[6] << 16)
                | ((ULONG)recvBuf[7] << 24);

    *OutStatus = recvStatus;

    /* 复制响应 JSON */
    if (recvDataLen > 0) {
        if (recvDataLen >= RespBufLen) {
            ntStatus = STATUS_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        RtlCopyMemory(RespBuf, recvBuf + 8, recvDataLen);
        RespBuf[recvDataLen] = '\0';
    } else {
        RespBuf[0] = '\0';
    }

    ntStatus = STATUS_SUCCESS;

cleanup:
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
    return ntStatus;
}
