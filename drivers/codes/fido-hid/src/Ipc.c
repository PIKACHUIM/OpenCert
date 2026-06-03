/*
 * Ipc.c - OpenCert FIDO2 HID 驱动 IPC 通信层
 *
 * 通过 Named Pipe 与 OpenCert client-card（Go 后端）通信。
 * 协议格式与 KSP/CSP 的 ipc_client.c 保持一致：
 *
 *   请求帧：[4字节命令码][4字节长度][JSON数据]
 *   响应帧：[4字节状态码][4字节长度][JSON数据]
 *
 * 此文件与 fido-umdf/src/Ipc.c 逻辑完全相同，
 * 仅头文件引用改为本项目的 Driver.h。
 */

#include "Driver.h"

/* ================================================================
 * IpcCall - 发送 IPC 请求并接收响应
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

    BYTE    sendBuf[IPC_BUF_MAX];
    ULONG   sendLen = 0;
    ULONG   jsonLen;

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
    sendBuf[0] = (BYTE)(CmdCode & 0xFF);
    sendBuf[1] = (BYTE)((CmdCode >> 8) & 0xFF);
    sendBuf[2] = (BYTE)((CmdCode >> 16) & 0xFF);
    sendBuf[3] = (BYTE)((CmdCode >> 24) & 0xFF);
    sendBuf[4] = (BYTE)(jsonLen & 0xFF);
    sendBuf[5] = (BYTE)((jsonLen >> 8) & 0xFF);
    sendBuf[6] = (BYTE)((jsonLen >> 16) & 0xFF);
    sendBuf[7] = (BYTE)((jsonLen >> 24) & 0xFF);
    RtlCopyMemory(sendBuf + 8, ReqJson, jsonLen);
    sendLen = 8 + jsonLen;

    /* ---- 连接 Named Pipe（等待最多 5 秒） ---- */
    if (!WaitNamedPipeA(IPC_PIPE_NAME_A, 5000)) {
        return STATUS_PIPE_NOT_AVAILABLE;
    }

    hPipe = CreateFileA(
        IPC_PIPE_NAME_A,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
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
    recvStatus = (ULONG)recvBuf[0]
               | ((ULONG)recvBuf[1] << 8)
               | ((ULONG)recvBuf[2] << 16)
               | ((ULONG)recvBuf[3] << 24);

    recvDataLen = (ULONG)recvBuf[4]
                | ((ULONG)recvBuf[5] << 8)
                | ((ULONG)recvBuf[6] << 16)
                | ((ULONG)recvBuf[7] << 24);

    *OutStatus = recvStatus;

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
