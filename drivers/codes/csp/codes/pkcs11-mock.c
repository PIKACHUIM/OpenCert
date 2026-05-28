/*
 *  Copyright 2011-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */


#include "pkcs11-mock.h"


CK_BBOOL pkcs11_mock_initialized = CK_FALSE;
CK_BBOOL pkcs11_mock_session_opened = CK_FALSE;
CK_ULONG pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
PKCS11_MOCK_CK_OPERATION pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
CK_OBJECT_HANDLE pkcs11_mock_find_result = CKR_OBJECT_HANDLE_INVALID;

/* IPC 相关全局状态 */
#define PKCS11_MOCK_MAX_FIND_RESULTS 64
static CK_OBJECT_HANDLE  pkcs11_mock_find_results[PKCS11_MOCK_MAX_FIND_RESULTS];
static CK_ULONG          pkcs11_mock_find_count = 0;
static CK_ULONG          pkcs11_mock_find_pos = 0;
static CK_MECHANISM_TYPE pkcs11_mock_sign_mechanism = 0;
static CK_OBJECT_HANDLE  pkcs11_mock_sign_key = 0;
static CK_MECHANISM_TYPE pkcs11_mock_decrypt_mechanism = 0;
static CK_OBJECT_HANDLE  pkcs11_mock_decrypt_key = 0;
static CK_MECHANISM_TYPE pkcs11_mock_encrypt_mechanism = 0;
static CK_OBJECT_HANDLE  pkcs11_mock_encrypt_key = 0;

/* ---- 摘要上下文（本地回退用）---- */
static CK_MECHANISM_TYPE pkcs11_mock_digest_mechanism = 0;
#define PKCS11_MOCK_DIGEST_BUF_MAX (1024 * 1024)  /* 本地回退最大 1MB */
static CK_BYTE  *pkcs11_mock_digest_buf = NULL;
static CK_ULONG  pkcs11_mock_digest_buf_len = 0;

/* 简易 SHA-1 / SHA-256 / SHA-384 / SHA-512 / MD5 本地实现（仅用于 IPC 不可用时的回退）*/
#ifdef _WIN32
#  include <wincrypt.h>
   /* Windows CryptoAPI 摘要辅助 */
   static int local_digest(CK_MECHANISM_TYPE mech, const CK_BYTE *data, CK_ULONG len,
                           CK_BYTE *out, CK_ULONG *out_len)
   {
       ALG_ID alg;
       CK_ULONG hash_size;
       switch (mech) {
           case CKM_MD5:    alg = CALG_MD5;    hash_size = 16; break;
           case CKM_SHA_1:  alg = CALG_SHA1;   hash_size = 20; break;
           case CKM_SHA256: alg = CALG_SHA_256; hash_size = 32; break;
           case CKM_SHA384: alg = CALG_SHA_384; hash_size = 48; break;
           case CKM_SHA512: alg = CALG_SHA_512; hash_size = 64; break;
           default: return -1;
       }
       if (out == NULL) { *out_len = hash_size; return 0; }
       if (*out_len < hash_size) { *out_len = hash_size; return -2; }
       HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
       if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return -1;
       if (!CryptCreateHash(hProv, alg, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return -1; }
       CryptHashData(hHash, data, (DWORD)len, 0);
       DWORD hl = (DWORD)hash_size;
       CryptGetHashParam(hHash, HP_HASHVAL, out, &hl, 0);
       *out_len = (CK_ULONG)hl;
       CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
       return 0;
   }
#else
   /* POSIX: 使用 OpenSSL EVP（链接 -lcrypto）*/
#  include <openssl/evp.h>
   static int local_digest(CK_MECHANISM_TYPE mech, const CK_BYTE *data, CK_ULONG len,
                           CK_BYTE *out, CK_ULONG *out_len)
   {
       const EVP_MD *md;
       CK_ULONG hash_size;
       switch (mech) {
           case CKM_MD5:    md = EVP_md5();    hash_size = 16; break;
           case CKM_SHA_1:  md = EVP_sha1();   hash_size = 20; break;
           case CKM_SHA256: md = EVP_sha256(); hash_size = 32; break;
           case CKM_SHA384: md = EVP_sha384(); hash_size = 48; break;
           case CKM_SHA512: md = EVP_sha512(); hash_size = 64; break;
           default: return -1;
       }
       if (out == NULL) { *out_len = hash_size; return 0; }
       if (*out_len < hash_size) { *out_len = hash_size; return -2; }
       unsigned int hl = 0;
       EVP_MD_CTX *ctx = EVP_MD_CTX_new();
       EVP_DigestInit_ex(ctx, md, NULL);
       EVP_DigestUpdate(ctx, data, (size_t)len);
       EVP_DigestFinal_ex(ctx, out, &hl);
       EVP_MD_CTX_free(ctx);
       *out_len = (CK_ULONG)hl;
       return 0;
   }
#endif

static CK_ULONG digest_hash_size(CK_MECHANISM_TYPE mech)
{
    switch (mech) {
        case CKM_MD5:    return 16;
        case CKM_SHA_1:  return 20;
        case CKM_SHA256: return 32;
        case CKM_SHA384: return 48;
        case CKM_SHA512: return 64;
        default:         return 0;
    }
}


CK_FUNCTION_LIST pkcs11_mock_2_40_functions =
{
	{0x02, 0x28},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};

CK_INTERFACE pkcs11_mock_2_40_interface =
{
	(CK_CHAR*)"PKCS 11",
	&pkcs11_mock_2_40_functions,
	0
};


CK_FUNCTION_LIST_3_0 pkcs11_mock_3_1_functions =
{
	{0x03, 0x01},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent,
	&C_GetInterfaceList,
	&C_GetInterface,
	&C_LoginUser,
	&C_SessionCancel,
	&C_MessageEncryptInit,
	&C_EncryptMessage,
	&C_EncryptMessageBegin,
	&C_EncryptMessageNext,
	&C_MessageEncryptFinal,
	&C_MessageDecryptInit,
	&C_DecryptMessage,
	&C_DecryptMessageBegin,
	&C_DecryptMessageNext,
	&C_MessageDecryptFinal,
	&C_MessageSignInit,
	&C_SignMessage,
	&C_SignMessageBegin,
	&C_SignMessageNext,
	&C_MessageSignFinal,
	&C_MessageVerifyInit,
	&C_VerifyMessage,
	&C_VerifyMessageBegin,
	&C_VerifyMessageNext,
	&C_MessageVerifyFinal
};


CK_INTERFACE pkcs11_mock_3_1_interface =
{
	(CK_CHAR*)"PKCS 11",
	&pkcs11_mock_3_1_functions,
	0
};


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (CK_TRUE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	IGNORE(pInitArgs);

	/* 建立 IPC 连接（最多重试 5 次，每次间隔 500ms）*/
	if (ipc_global_connect() != 0) {
		/* client-card 未启动时降级为 Mock 模式，不阻止初始化 */
		/* 后续 IPC 调用会检查连接状态并返回 CKR_DEVICE_REMOVED */
	}

	pkcs11_mock_initialized = CK_TRUE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(pReserved);

	/* 断开 IPC 连接 */
	ipc_global_disconnect();

	pkcs11_mock_initialized = CK_FALSE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 获取库信息 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_INFO, NULL, &resp, &rv);
		if (ret == 0 && rv == CKR_OK && resp != NULL) {
			/* 解析响应中的库信息 */
			const char *manufacturer = json_get_string(resp, "manufacturer_id");
			const char *description = json_get_string(resp, "library_description");
			int lib_major = json_get_int(resp, "library_version_major", 1);
			int lib_minor = json_get_int(resp, "library_version_minor", 0);

			pInfo->cryptokiVersion.major = 0x02;
			pInfo->cryptokiVersion.minor = 0x14;
			pInfo->flags = 0;

			memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
			if (manufacturer) {
				size_t len = strlen(manufacturer);
				if (len > sizeof(pInfo->manufacturerID)) len = sizeof(pInfo->manufacturerID);
				memcpy(pInfo->manufacturerID, manufacturer, len);
			}

			memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
			if (description) {
				size_t len = strlen(description);
				if (len > sizeof(pInfo->libraryDescription)) len = sizeof(pInfo->libraryDescription);
				memcpy(pInfo->libraryDescription, description, len);
			}

			pInfo->libraryVersion.major = (CK_BYTE)lib_major;
			pInfo->libraryVersion.minor = (CK_BYTE)lib_minor;

			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
	}

	/* IPC 不可用时回退到硬编码值 */
	pInfo->cryptokiVersion.major = 0x02;
	pInfo->cryptokiVersion.minor = 0x14;
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_INFO_MANUFACTURER_ID));
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, PKCS11_MOCK_CK_INFO_LIBRARY_DESCRIPTION, strlen(PKCS11_MOCK_CK_INFO_LIBRARY_DESCRIPTION));
	pInfo->libraryVersion.major = PKCS11_MOCK_CK_INFO_LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = PKCS11_MOCK_CK_INFO_LIBRARY_VERSION_MINOR;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_mock_2_40_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 获取真实 Slot 列表 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"token_present\":%s}", tokenPresent ? "true" : "false");

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_SLOT_LIST, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			/* 解析 slot_ids 数组：{"rv":0,"data":{"slot_ids":[1,2,3],"count":3}} */
			uint32_t count = 0;
			json_get_uint32(resp, "count", &count);

			if (NULL == pSlotList) {
				*pulCount = count;
				free(resp);
				return CKR_OK;
			}

			if (*pulCount < count) {
				free(resp);
				*pulCount = count;
				return CKR_BUFFER_TOO_SMALL;
			}

			/* 解析 slot_ids 数组 */
			const char *arr = strstr(resp, "\"slot_ids\":[");
			if (arr != NULL) {
				arr += strlen("\"slot_ids\":[");
				CK_ULONG i = 0;
				while (i < count && *arr && *arr != ']') {
					pSlotList[i++] = (CK_SLOT_ID)strtoul(arr, (char **)&arr, 10);
					while (*arr == ',' || *arr == ' ') arr++;
				}
				*pulCount = i;
			} else {
				*pulCount = 0;
			}
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级到 Mock */
	}

	/* Mock 降级：返回单个固定 Slot */
	IGNORE(tokenPresent);
	if (NULL == pSlotList) {
		*pulCount = 1;
	} else {
		if (0 == *pulCount)
			return CKR_BUFFER_TOO_SMALL;
		pSlotList[0] = PKCS11_MOCK_CK_SLOT_ID;
		*pulCount = 1;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 获取 Slot 信息 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"slot_id\":%lu}", (unsigned long)slotID);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_SLOT_INFO, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == CKR_OK && resp != NULL) {
			const char *desc = json_get_string(resp, "slot_description");
			const char *mfr = json_get_string(resp, "manufacturer_id");

			memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
			if (desc) {
				size_t len = strlen(desc);
				if (len > sizeof(pInfo->slotDescription)) len = sizeof(pInfo->slotDescription);
				memcpy(pInfo->slotDescription, desc, len);
			}
			memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
			if (mfr) {
				size_t len = strlen(mfr);
				if (len > sizeof(pInfo->manufacturerID)) len = sizeof(pInfo->manufacturerID);
				memcpy(pInfo->manufacturerID, mfr, len);
			}
			pInfo->flags = (CK_FLAGS)json_get_int(resp, "flags", CKF_TOKEN_PRESENT);
			pInfo->hardwareVersion.major = (CK_BYTE)json_get_int(resp, "hw_major", 1);
			pInfo->hardwareVersion.minor = (CK_BYTE)json_get_int(resp, "hw_minor", 0);
			pInfo->firmwareVersion.major = (CK_BYTE)json_get_int(resp, "fw_major", 1);
			pInfo->firmwareVersion.minor = (CK_BYTE)json_get_int(resp, "fw_minor", 0);

			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	/* IPC 不可用时回退到硬编码值 */
	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, PKCS11_MOCK_CK_SLOT_INFO_SLOT_DESCRIPTION, strlen(PKCS11_MOCK_CK_SLOT_INFO_SLOT_DESCRIPTION));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_SLOT_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_SLOT_INFO_MANUFACTURER_ID));
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 获取真实 Token 信息 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"slot_id\":%lu}", (unsigned long)slotID);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_TOKEN_INFO, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			/* 解析 label、manufacturer_id、model、serial_number、flags */
			char *label_s = json_get_string(resp, "label");
			char *mfr_s = json_get_string(resp, "manufacturer_id");
			char *model_s = json_get_string(resp, "model");
			char *serial_s = json_get_string(resp, "serial_number");
			uint32_t flags32 = 0;
			json_get_uint32(resp, "flags", &flags32);

			memset(pInfo->label, ' ', sizeof(pInfo->label));
			if (label_s) { memcpy(pInfo->label, label_s, strlen(label_s) < 32 ? strlen(label_s) : 32); free(label_s); }
			memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
			if (mfr_s) { memcpy(pInfo->manufacturerID, mfr_s, strlen(mfr_s) < 32 ? strlen(mfr_s) : 32); free(mfr_s); }
			memset(pInfo->model, ' ', sizeof(pInfo->model));
			if (model_s) { memcpy(pInfo->model, model_s, strlen(model_s) < 16 ? strlen(model_s) : 16); free(model_s); }
			memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
			if (serial_s) { memcpy(pInfo->serialNumber, serial_s, strlen(serial_s) < 16 ? strlen(serial_s) : 16); free(serial_s); }
			pInfo->flags = flags32 ? (CK_FLAGS)flags32 : (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED);
			pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
			pInfo->ulSessionCount = (CK_TRUE == pkcs11_mock_session_opened) ? 1 : 0;
			pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
			pInfo->ulRwSessionCount = ((CK_TRUE == pkcs11_mock_session_opened) && ((CKS_RO_PUBLIC_SESSION != pkcs11_mock_session_state) && (CKS_RO_USER_FUNCTIONS != pkcs11_mock_session_state))) ? 1 : 0;
			pInfo->ulMaxPinLen = PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN;
			pInfo->ulMinPinLen = PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN;
			pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
			pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
			pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
			pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
			pInfo->hardwareVersion.major = 0x01;
			pInfo->hardwareVersion.minor = 0x00;
			pInfo->firmwareVersion.major = 0x01;
			pInfo->firmwareVersion.minor = 0x00;
			memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级到硬编码 */
	}

	/* 硬编码降级 */
	memset(pInfo->label, ' ', sizeof(pInfo->label));
	memcpy(pInfo->label, PKCS11_MOCK_CK_TOKEN_INFO_LABEL, strlen(PKCS11_MOCK_CK_TOKEN_INFO_LABEL));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MOCK_CK_TOKEN_INFO_MANUFACTURER_ID, strlen(PKCS11_MOCK_CK_TOKEN_INFO_MANUFACTURER_ID));
	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memcpy(pInfo->model, PKCS11_MOCK_CK_TOKEN_INFO_MODEL, strlen(PKCS11_MOCK_CK_TOKEN_INFO_MODEL));
	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	memcpy(pInfo->serialNumber, PKCS11_MOCK_CK_TOKEN_INFO_SERIAL_NUMBER, strlen(PKCS11_MOCK_CK_TOKEN_INFO_SERIAL_NUMBER));
	pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = (CK_TRUE == pkcs11_mock_session_opened) ? 1 : 0;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = ((CK_TRUE == pkcs11_mock_session_opened) && ((CKS_RO_PUBLIC_SESSION != pkcs11_mock_session_state) && (CKS_RO_USER_FUNCTIONS != pkcs11_mock_session_state))) ? 1 : 0;
	pInfo->ulMaxPinLen = PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN;
	pInfo->ulMinPinLen = PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;
	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 获取真实机制列表 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"slot_id\":%lu}", (unsigned long)slotID);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_MECHANISM_LIST, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			/* 解析 mechanisms 数组：{"rv":0,"data":{"mechanisms":[262,3,...], "count":N}} */
			uint32_t count32 = 0;
			json_get_uint32(resp, "count", &count32);
			unsigned long count = (unsigned long)count32;

			if (NULL == pMechanismList) {
				*pulCount = (CK_ULONG)count;
				free(resp);
				return CKR_OK;
			}

			if (*pulCount < (CK_ULONG)count) {
				free(resp);
				return CKR_BUFFER_TOO_SMALL;
			}

			/* 解析 mechanisms 数组 */
			const char *arr = strstr(resp, "\"mechanisms\":[");
			if (arr != NULL) {
				arr += strlen("\"mechanisms\":[");
				CK_ULONG i = 0;
				while (i < (CK_ULONG)count && *arr != ']' && *arr != '\0') {
					while (*arr == ' ' || *arr == ',') arr++;
					if (*arr == ']' || *arr == '\0') break;
					unsigned long mech = 0;
					mech = strtoul(arr, NULL, 10);
					pMechanismList[i++] = (CK_MECHANISM_TYPE)mech;
					while (*arr != ',' && *arr != ']' && *arr != '\0') arr++;
				}
				*pulCount = i;
			}
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级到硬编码 */
	}

	/* 硬编码降级 */
	if (NULL == pMechanismList)
	{
		*pulCount = 9;
	}
	else
	{
		if (9 > *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
		pMechanismList[1] = CKM_RSA_PKCS;
		pMechanismList[2] = CKM_SHA1_RSA_PKCS;
		pMechanismList[3] = CKM_RSA_PKCS_OAEP;
		pMechanismList[4] = CKM_DES3_CBC;
		pMechanismList[5] = CKM_DES3_KEY_GEN;
		pMechanismList[6] = CKM_SHA_1;
		pMechanismList[7] = CKM_XOR_BASE_AND_DATA;
		pMechanismList[8] = CKM_AES_CBC;

		*pulCount = 9;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 获取真实机制信息 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"slot_id\":%lu,\"mechanism\":%lu}",
			(unsigned long)slotID, (unsigned long)type);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_MECHANISM_INFO, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			uint32_t min_key32 = 0, max_key32 = 0, flags32 = 0;
			json_get_uint32(resp, "min_key_size", &min_key32);
			json_get_uint32(resp, "max_key_size", &max_key32);
			json_get_uint32(resp, "flags", &flags32);
			pInfo->ulMinKeySize = (CK_ULONG)min_key32;
			pInfo->ulMaxKeySize = (CK_ULONG)max_key32;
			pInfo->flags = (CK_FLAGS)flags32;
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级到硬编码 */
	}

	/* 硬编码降级 */
	switch (type)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;

		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER | CKF_WRAP | CKF_UNWRAP;
			break;

		case CKM_SHA1_RSA_PKCS:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;

		case CKM_RSA_PKCS_OAEP:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		case CKM_DES3_CBC:
			pInfo->ulMinKeySize = 192;
			pInfo->ulMaxKeySize = 192;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		case CKM_DES3_KEY_GEN:
			pInfo->ulMinKeySize = 192;
			pInfo->ulMaxKeySize = 192;
			pInfo->flags = CKF_GENERATE;
			break;

		case CKM_SHA_1:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;

		case CKM_XOR_BASE_AND_DATA:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_DERIVE;
			break;

		case CKM_AES_CBC:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pLabel)
		return CKR_ARGUMENTS_BAD;

	if (CK_TRUE == pkcs11_mock_session_opened)
		return CKR_SESSION_EXISTS;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (CKS_RW_SO_FUNCTIONS != pkcs11_mock_session_state)
		return CKR_USER_NOT_LOGGED_IN;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		char pin_str[PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN + 1];
		memcpy(pin_str, pPin, ulPinLen);
		pin_str[ulPinLen] = '\0';

		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"pin\":\"%s\"}",
			(unsigned long)hSession, pin_str);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_INIT_PIN, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0) return (CK_RV)rv;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((CKS_RO_PUBLIC_SESSION == pkcs11_mock_session_state) || (CKS_RO_USER_FUNCTIONS == pkcs11_mock_session_state))
		return CKR_SESSION_READ_ONLY;

	if (NULL == pOldPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulOldLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulOldLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pNewPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulNewLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulNewLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		char old_str[PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN + 1];
		char new_str[PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN + 1];
		memcpy(old_str, pOldPin, ulOldLen); old_str[ulOldLen] = '\0';
		memcpy(new_str, pNewPin, ulNewLen); new_str[ulNewLen] = '\0';

		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"old_pin\":\"%s\",\"new_pin\":\"%s\"}",
			(unsigned long)hSession, old_str, new_str);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_SET_PIN, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0) return (CK_RV)rv;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (CK_TRUE == pkcs11_mock_session_opened)
		return CKR_SESSION_COUNT;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	IGNORE(pApplication);
	IGNORE(Notify);

	if (NULL == phSession)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 创建会话 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"slot_id\":%lu,\"flags\":%lu}",
			(unsigned long)slotID, (unsigned long)flags);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_OPEN_SESSION, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			uint32_t session_id = PKCS11_MOCK_CK_SESSION_ID;
			json_get_uint32(resp, "session_id", &session_id);
			free(resp);

			pkcs11_mock_session_opened = CK_TRUE;
			pkcs11_mock_session_state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
			*phSession = (CK_SESSION_HANDLE)session_id;
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级 */
	}

	/* Mock 降级 */
	pkcs11_mock_session_opened = CK_TRUE;
	pkcs11_mock_session_state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	*phSession = PKCS11_MOCK_CK_SESSION_ID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	/* 通过 IPC 关闭会话 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu}", (unsigned long)hSession);
		char *resp = NULL;
		uint32_t rv = 0;
		ipc_call(fd, CMD_CLOSE_SESSION, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);
	}

	pkcs11_mock_session_opened = CK_FALSE;
	pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"slot_id\":%lu}", (unsigned long)slotID);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_CLOSE_ALL_SESSIONS, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0 && rv == CKR_OK) {
			pkcs11_mock_session_opened = CK_FALSE;
			pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
			return CKR_OK;
		}
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	pkcs11_mock_session_opened = CK_FALSE;
	pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu}", (unsigned long)hSession);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_SESSION_INFO, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == CKR_OK && resp != NULL) {
			pInfo->slotID = (CK_SLOT_ID)json_get_int(resp, "slot_id", 0);
			pInfo->state = (CK_STATE)json_get_int(resp, "state", CKS_RO_PUBLIC_SESSION);
			pInfo->flags = (CK_FLAGS)json_get_int(resp, "flags", CKF_SERIAL_SESSION);
			pInfo->ulDeviceError = 0;
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	/* IPC 不可用时回退到本地状态 */
	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pInfo->slotID = PKCS11_MOCK_CK_SLOT_ID;
	pInfo->state = pkcs11_mock_session_state;
	pInfo->flags = CKF_SERIAL_SESSION;
	if ((pkcs11_mock_session_state != CKS_RO_PUBLIC_SESSION) && (pkcs11_mock_session_state != CKS_RO_USER_FUNCTIONS))
		pInfo->flags = pInfo->flags | CKF_RW_SESSION;
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pOperationState)
	{
		*pulOperationStateLen = 256;
	}
	else
	{
		if (256 > *pulOperationStateLen)
			return CKR_BUFFER_TOO_SMALL;

		memset(pOperationState, 1, 256);
		*pulOperationStateLen = 256;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pOperationState)
		return CKR_ARGUMENTS_BAD;

	if (256 != ulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	IGNORE(hEncryptionKey);

	IGNORE(hAuthenticationKey);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((CKU_SO != userType) && (CKU_USER != userType))
		return CKR_USER_TYPE_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_MOCK_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	/* 通过 IPC 转发 Login（PIN 验证由 client-card 完成）*/
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		/* 将 PIN 作为字符串传递（最大 32 字节，已由上面检查）*/
		char pin_str[PKCS11_MOCK_CK_TOKEN_INFO_MAX_PIN_LEN + 1];
		memcpy(pin_str, pPin, ulPinLen);
		pin_str[ulPinLen] = '\0';

		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"user_type\":%lu,\"pin\":\"%s\"}",
			(unsigned long)hSession, (unsigned long)userType, pin_str);

		char *resp = NULL;
		uint32_t ipc_rv = 0;
		int ret = ipc_call(fd, CMD_LOGIN, req.buf, &resp, &ipc_rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0) {
			if (ipc_rv != IPC_CKR_OK)
				return (CK_RV)ipc_rv;
			/* 登录成功，更新本地状态 */
			goto update_state;
		}
		/* IPC 失败，降级 */
	}

update_state:
	switch (pkcs11_mock_session_state)
	{
		case CKS_RO_PUBLIC_SESSION:
			if (CKU_SO == userType)
				rv = CKR_SESSION_READ_ONLY_EXISTS;
			else
				pkcs11_mock_session_state = CKS_RO_USER_FUNCTIONS;
			break;

		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:
			rv = (CKU_SO == userType) ? CKR_USER_ANOTHER_ALREADY_LOGGED_IN : CKR_USER_ALREADY_LOGGED_IN;
			break;

		case CKS_RW_PUBLIC_SESSION:
			pkcs11_mock_session_state = (CKU_SO == userType) ? CKS_RW_SO_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
			break;

		case CKS_RW_SO_FUNCTIONS:
			rv = (CKU_SO == userType) ? CKR_USER_ALREADY_LOGGED_IN : CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
			break;
	}

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu}", (unsigned long)hSession);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_LOGOUT, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0 && rv == CKR_OK) {
			/* 更新本地状态 */
			if (pkcs11_mock_session_state == CKS_RO_USER_FUNCTIONS)
				pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
			else if (pkcs11_mock_session_state == CKS_RW_USER_FUNCTIONS || pkcs11_mock_session_state == CKS_RW_SO_FUNCTIONS)
				pkcs11_mock_session_state = CKS_RW_PUBLIC_SESSION;
			return CKR_OK;
		}
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	/* IPC 不可用时回退到本地状态 */
	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((pkcs11_mock_session_state == CKS_RO_PUBLIC_SESSION) || (pkcs11_mock_session_state == CKS_RW_PUBLIC_SESSION))
		return CKR_USER_NOT_LOGGED_IN;

	if (pkcs11_mock_session_state == CKS_RO_USER_FUNCTIONS)
		pkcs11_mock_session_state = CKS_RO_PUBLIC_SESSION;
	else if (pkcs11_mock_session_state == CKS_RW_USER_FUNCTIONS || pkcs11_mock_session_state == CKS_RW_SO_FUNCTIONS)
		pkcs11_mock_session_state = CKS_RW_PUBLIC_SESSION;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phObject)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"attr_count\":%lu}",
			(unsigned long)hSession, (unsigned long)ulCount);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_CREATE_OBJECT, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == CKR_OK && resp != NULL) {
			*phObject = (CK_OBJECT_HANDLE)json_get_int(resp, "handle", PKCS11_MOCK_CK_OBJECT_HANDLE_DATA);
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	*phObject = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject)
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == phNewObject)
		return CKR_ARGUMENTS_BAD;

	if ((NULL != pTemplate) && (0 < ulCount))
	{
		for (i = 0; i < ulCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	*phNewObject = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"handle\":%lu}",
			(unsigned long)hSession, (unsigned long)hObject);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_DESTROY_OBJECT, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0) return (CK_RV)rv;
	}

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pulSize)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 获取真实对象大小 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"object_handle\":%lu}",
			(unsigned long)hSession, (unsigned long)hObject);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_OBJECT_SIZE, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			uint32_t size32 = 0;
			json_get_uint32(resp, "size", &size32);
			*pulSize = (CK_ULONG)size32;
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级到硬编码 */
	}

	/* 硬编码降级 */
	*pulSize = PKCS11_MOCK_CK_OBJECT_SIZE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 获取真实属性 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"object_handle\":%lu,\"types\":[",
			(unsigned long)hSession, (unsigned long)hObject);

		for (i = 0; i < ulCount; i++) {
			if (i > 0) json_buf_append(&req, ",");
			json_buf_appendf(&req, "%lu", (unsigned long)pTemplate[i].type);
		}
		json_buf_append(&req, "]}");

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GET_ATTRIBUTE_VALUE, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			/* 解析 attrs 数组：{"rv":0,"data":{"attrs":[{"type":3,"value":"base64..."},...]}} */
			const char *attrs_pos = strstr(resp, "\"attrs\":[");
			if (attrs_pos != NULL) {
				/* 简单逐个解析每个属性 */
				for (i = 0; i < ulCount; i++) {
					/* 在 attrs 数组中查找对应 type 的 value */
					char type_pattern[64];
					snprintf(type_pattern, sizeof(type_pattern),
						"\"type\":%lu", (unsigned long)pTemplate[i].type);
					const char *attr_pos = strstr(attrs_pos, type_pattern);
					if (attr_pos == NULL) {
						pTemplate[i].ulValueLen = (CK_ULONG)-1; /* 不支持 */
						continue;
					}

					/* 找到 value 字段 */
					uint8_t *val_data = NULL;
					size_t val_len = 0;
					/* 在当前 attr 对象范围内查找 value */
					char local_json[4096];
					size_t copy_len = sizeof(local_json) - 1;
					size_t remaining = strlen(attr_pos);
					if (remaining < copy_len) copy_len = remaining;
					memcpy(local_json, attr_pos, copy_len);
					local_json[copy_len] = '\0';

					if (json_get_b64(local_json, "value", &val_data, &val_len) == 0) {
						if (pTemplate[i].pValue != NULL) {
							if (pTemplate[i].ulValueLen < (CK_ULONG)val_len) {
								free(val_data);
								pTemplate[i].ulValueLen = (CK_ULONG)val_len;
								free(resp);
								return CKR_BUFFER_TOO_SMALL;
							}
							memcpy(pTemplate[i].pValue, val_data, val_len);
						}
						pTemplate[i].ulValueLen = (CK_ULONG)val_len;
						free(val_data);
					} else {
						pTemplate[i].ulValueLen = (CK_ULONG)-1;
					}
				}
			}
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级 */
	}

	/* Mock 降级 */
	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	for (i = 0; i < ulCount; i++) {
		if (CKA_LABEL == pTemplate[i].type) {
			if (NULL != pTemplate[i].pValue) {
				if (pTemplate[i].ulValueLen < strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL))
					return CKR_BUFFER_TOO_SMALL;
				else
					memcpy(pTemplate[i].pValue, PKCS11_MOCK_CK_OBJECT_CKA_LABEL, strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL));
			}
			pTemplate[i].ulValueLen = strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL);
		} else if (CKA_VALUE == pTemplate[i].type) {
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY == hObject) {
				pTemplate[i].ulValueLen = (CK_ULONG)-1;
			} else {
				if (NULL != pTemplate[i].pValue) {
					if (pTemplate[i].ulValueLen < strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE))
						return CKR_BUFFER_TOO_SMALL;
					else
						memcpy(pTemplate[i].pValue, PKCS11_MOCK_CK_OBJECT_CKA_VALUE, strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE));
				}
				pTemplate[i].ulValueLen = strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE);
			}
		} else {
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 设置属性 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"object_handle\":%lu,\"attrs\":[",
			(unsigned long)hSession, (unsigned long)hObject);

		for (i = 0; i < ulCount; i++) {
			if (NULL == pTemplate[i].pValue || 0 >= pTemplate[i].ulValueLen)
				continue;
			if (i > 0) json_buf_append(&req, ",");
			json_buf_appendf(&req, "{\"type\":%lu,\"value\":",
				(unsigned long)pTemplate[i].type);
			json_buf_append_b64(&req,
				(const uint8_t *)pTemplate[i].pValue,
				(size_t)pTemplate[i].ulValueLen);
			json_buf_append(&req, "}");
		}
		json_buf_append(&req, "]}");

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_SET_ATTRIBUTE_VALUE, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0 && rv == IPC_CKR_OK) {
			return CKR_OK;
		}
		/* IPC 失败，降级到硬编码 */
	}

	/* 硬编码降级 */
	for (i = 0; i < ulCount; i++)
	{
		if ((CKA_LABEL == pTemplate[i].type) || (CKA_VALUE == pTemplate[i].type))
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else
		{
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;
	CK_ULONG_PTR cka_class_value = NULL;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	/* 重置查找结果 */
	pkcs11_mock_find_count = 0;
	pkcs11_mock_find_pos = 0;
	pkcs11_mock_find_result = CK_INVALID_HANDLE;

	/* 通过 IPC 获取真实对象列表 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		/* 构建模板 JSON */
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"template\":[", (unsigned long)hSession);

		for (i = 0; i < ulCount; i++) {
			if (NULL == pTemplate[i].pValue || 0 >= pTemplate[i].ulValueLen)
				continue;
			if (i > 0) json_buf_append(&req, ",");
			json_buf_appendf(&req, "{\"type\":%lu,\"value\":",
				(unsigned long)pTemplate[i].type);
			json_buf_append_b64(&req,
				(const uint8_t *)pTemplate[i].pValue,
				(size_t)pTemplate[i].ulValueLen);
			json_buf_append(&req, "}");
		}
		json_buf_append(&req, "]}");

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_FIND_OBJECTS_INIT, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			/* 解析 handles 数组：{"rv":0,"data":{"handles":[1,2,3],"count":3}} */
			uint32_t count = 0;
			json_get_uint32(resp, "count", &count);
			if (count > PKCS11_MOCK_MAX_FIND_RESULTS)
				count = PKCS11_MOCK_MAX_FIND_RESULTS;

			const char *arr = strstr(resp, "\"handles\":[");
			if (arr != NULL) {
				arr += strlen("\"handles\":[");
				CK_ULONG k = 0;
				while (k < count && *arr && *arr != ']') {
					pkcs11_mock_find_results[k++] = (CK_OBJECT_HANDLE)strtoul(arr, (char **)&arr, 10);
					while (*arr == ',' || *arr == ' ') arr++;
				}
				pkcs11_mock_find_count = k;
			}
			free(resp);
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_FIND;
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级 */
	}

	/* Mock 降级：根据模板中的 CKA_CLASS 返回固定对象 */
	IGNORE(ulCount);
	for (i = 0; i < ulCount; i++) {
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (CKA_CLASS == pTemplate[i].type) {
			if (sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			cka_class_value = (CK_ULONG_PTR)pTemplate[i].pValue;
			switch (*cka_class_value) {
				case CKO_DATA:
					pkcs11_mock_find_results[0] = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;
					pkcs11_mock_find_results[1] = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;
					pkcs11_mock_find_count = 2;
					break;
				case CKO_SECRET_KEY:
					pkcs11_mock_find_results[0] = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;
					pkcs11_mock_find_count = 1;
					break;
				case CKO_PUBLIC_KEY:
					pkcs11_mock_find_results[0] = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
					pkcs11_mock_find_count = 1;
					break;
				case CKO_PRIVATE_KEY:
					pkcs11_mock_find_results[0] = PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;
					pkcs11_mock_find_count = 1;
					break;
				default:
					pkcs11_mock_find_count = 0;
					break;
			}
		}
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_FIND;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_FIND != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((NULL == phObject) && (0 < ulMaxObjectCount))
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulObjectCount)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"max_count\":%lu}",
			(unsigned long)hSession, (unsigned long)ulMaxObjectCount);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_FIND_OBJECTS, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == CKR_OK && resp != NULL) {
			/* 解析返回的对象句柄数组 */
			int count = json_get_int(resp, "count", 0);
			if (count > (int)ulMaxObjectCount) count = (int)ulMaxObjectCount;
			for (int i = 0; i < count; i++) {
				char key[32];
				snprintf(key, sizeof(key), "handles[%d]", i);
				phObject[i] = (CK_OBJECT_HANDLE)json_get_int(resp, key, 0);
			}
			*pulObjectCount = (CK_ULONG)count;
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	/* IPC 不可用时回退到本地状态 */
	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	CK_ULONG returned = 0;
	while (returned < ulMaxObjectCount && pkcs11_mock_find_pos < pkcs11_mock_find_count) {
		phObject[returned++] = pkcs11_mock_find_results[pkcs11_mock_find_pos++];
	}
	*pulObjectCount = returned;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_FIND != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu}", (unsigned long)hSession);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_FIND_OBJECTS_FINAL, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0 && rv == CKR_OK) {
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
			return CKR_OK;
		}
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 EncryptInit */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"mechanism\":%lu,\"key_handle\":%lu}",
			(unsigned long)hSession,
			(unsigned long)pMechanism->mechanism,
			(unsigned long)hKey);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_ENCRYPT_INIT, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0) {
			if (rv != IPC_CKR_OK) return (CK_RV)rv;
			pkcs11_mock_encrypt_mechanism = pMechanism->mechanism;
			pkcs11_mock_encrypt_key = hKey;
			switch (pkcs11_mock_active_operation) {
				case PKCS11_MOCK_CK_OPERATION_NONE:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT; break;
				case PKCS11_MOCK_CK_OPERATION_DIGEST:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT; break;
				case PKCS11_MOCK_CK_OPERATION_SIGN:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT; break;
				default: return CKR_FUNCTION_FAILED;
			}
			return CKR_OK;
		}
		/* IPC 失败，降级 */
	}

	/* Mock 降级 */
	switch (pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;
			break;
		case CKM_RSA_PKCS_OAEP:
			if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;
			break;
		case CKM_DES3_CBC:
			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;
			break;
		case CKM_AES_CBC:
			if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_encrypt_mechanism = pMechanism->mechanism;
	pkcs11_mock_encrypt_key = hKey;

	switch (pkcs11_mock_active_operation) {
		case PKCS11_MOCK_CK_OPERATION_NONE:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT; break;
		case PKCS11_MOCK_CK_OPERATION_DIGEST:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT; break;
		case PKCS11_MOCK_CK_OPERATION_SIGN:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT; break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发加密 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"key_handle\":%lu,\"mechanism\":%lu,\"data\":",
			(unsigned long)hSession,
			(unsigned long)pkcs11_mock_encrypt_key,
			(unsigned long)pkcs11_mock_encrypt_mechanism);
		json_buf_append_b64(&req, pData, (size_t)ulDataLen);
		json_buf_append(&req, "}");

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_ENCRYPT, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			uint8_t *enc_data = NULL;
			size_t enc_len = 0;
			if (json_get_b64(resp, "ciphertext", &enc_data, &enc_len) == 0) {
				if (NULL == pEncryptedData) {
					*pulEncryptedDataLen = (CK_ULONG)enc_len;
					free(enc_data);
					free(resp);
					return CKR_OK;
				}
				if (*pulEncryptedDataLen < (CK_ULONG)enc_len) {
					*pulEncryptedDataLen = (CK_ULONG)enc_len;
					free(enc_data);
					free(resp);
					return CKR_BUFFER_TOO_SMALL;
				}
				memcpy(pEncryptedData, enc_data, enc_len);
				*pulEncryptedDataLen = (CK_ULONG)enc_len;
				free(enc_data);
				free(resp);
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				return CKR_OK;
			}
			free(resp);
		}
		if (resp) free(resp);
		/* IPC 失败，降级 */
	}

	/* Mock 降级：XOR 0xAB */
	if (NULL != pEncryptedData) {
		if (ulDataLen > *pulEncryptedDataLen)
			return CKR_BUFFER_TOO_SMALL;
		for (i = 0; i < ulDataLen; i++)
			pEncryptedData[i] = pData[i] ^ 0xAB;
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
	}
	*pulEncryptedDataLen = ulDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulLastEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pLastEncryptedPart)
	{
		switch (pkcs11_mock_active_operation)
		{
			case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				break;
			case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
				break;
			case PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	*pulLastEncryptedPartLen = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 DecryptInit */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"mechanism\":%lu,\"key_handle\":%lu}",
			(unsigned long)hSession,
			(unsigned long)pMechanism->mechanism,
			(unsigned long)hKey);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_DECRYPT_INIT, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0) {
			if (rv != IPC_CKR_OK) return (CK_RV)rv;
			pkcs11_mock_decrypt_mechanism = pMechanism->mechanism;
			pkcs11_mock_decrypt_key = hKey;
			switch (pkcs11_mock_active_operation) {
				case PKCS11_MOCK_CK_OPERATION_NONE:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT; break;
				case PKCS11_MOCK_CK_OPERATION_DIGEST:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST; break;
				case PKCS11_MOCK_CK_OPERATION_VERIFY:
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY; break;
				default: return CKR_FUNCTION_FAILED;
			}
			return CKR_OK;
		}
		/* IPC 失败，降级 */
	}

	/* Mock 降级 */
	switch (pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;
			break;
		case CKM_RSA_PKCS_OAEP:
			if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;
			break;
		case CKM_DES3_CBC:
			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;
			break;
		case CKM_AES_CBC:
			if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_decrypt_mechanism = pMechanism->mechanism;
	pkcs11_mock_decrypt_key = hKey;

	switch (pkcs11_mock_active_operation) {
		case PKCS11_MOCK_CK_OPERATION_NONE:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT; break;
		case PKCS11_MOCK_CK_OPERATION_DIGEST:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST; break;
		case PKCS11_MOCK_CK_OPERATION_VERIFY:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY; break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发解密 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"key_handle\":%lu,\"mechanism\":%lu,\"data\":",
			(unsigned long)hSession,
			(unsigned long)pkcs11_mock_decrypt_key,
			(unsigned long)pkcs11_mock_decrypt_mechanism);
		json_buf_append_b64(&req, pEncryptedData, (size_t)ulEncryptedDataLen);
		json_buf_append(&req, "}");

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_DECRYPT, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			uint8_t *plain_data = NULL;
			size_t plain_len = 0;
			if (json_get_b64(resp, "plaintext", &plain_data, &plain_len) == 0) {
				if (NULL == pData) {
					*pulDataLen = (CK_ULONG)plain_len;
					free(plain_data);
					free(resp);
					return CKR_OK;
				}
				if (*pulDataLen < (CK_ULONG)plain_len) {
					*pulDataLen = (CK_ULONG)plain_len;
					free(plain_data);
					free(resp);
					return CKR_BUFFER_TOO_SMALL;
				}
				memcpy(pData, plain_data, plain_len);
				*pulDataLen = (CK_ULONG)plain_len;
				free(plain_data);
				free(resp);
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				return CKR_OK;
			}
			free(resp);
		}
		if (resp) free(resp);
		/* IPC 失败，降级 */
	}

	/* Mock 降级：XOR 0xAB */
	if (NULL != pData) {
		if (ulEncryptedDataLen > *pulDataLen)
			return CKR_BUFFER_TOO_SMALL;
		for (i = 0; i < ulEncryptedDataLen; i++)
			pData[i] = pEncryptedData[i] ^ 0xAB;
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
	}
	*pulDataLen = ulEncryptedDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulLastPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pLastPart)
	{
		switch (pkcs11_mock_active_operation)
		{
			case PKCS11_MOCK_CK_OPERATION_DECRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				break;
			case PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
				break;
			case PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	*pulLastPartLen = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"mechanism\":%lu}",
			(unsigned long)hSession, (unsigned long)pMechanism->mechanism);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_DIGEST_INIT, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0 && rv == CKR_OK) {
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
			return CKR_OK;
		}
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	/* IPC 不可用时回退到本地逻辑 */
	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	/* 支持多种摘要机制 */
	switch (pMechanism->mechanism) {
		case CKM_MD5:
		case CKM_SHA_1:
		case CKM_SHA256:
		case CKM_SHA384:
		case CKM_SHA512:
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	/* 初始化摘要上下文 */
	pkcs11_mock_digest_mechanism = pMechanism->mechanism;
	if (pkcs11_mock_digest_buf) { free(pkcs11_mock_digest_buf); pkcs11_mock_digest_buf = NULL; }
	pkcs11_mock_digest_buf_len = 0;

	switch (pkcs11_mock_active_operation)
	{
		case PKCS11_MOCK_CK_OPERATION_NONE:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST;
			break;
		case PKCS11_MOCK_CK_OPERATION_ENCRYPT:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT;
			break;
		case PKCS11_MOCK_CK_OPERATION_DECRYPT:
			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST;
			break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (NULL == pData || 0 >= ulDataLen || NULL == pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		char *data_b64 = base64_encode(pData, ulDataLen);
		if (data_b64) {
			json_buf_t req;
			json_buf_init(&req);
			json_buf_appendf(&req, "{\"session_id\":%lu,\"data\":\"%s\"}",
				(unsigned long)hSession, data_b64);
			free(data_b64);

			char *resp = NULL;
			uint32_t rv = 0;
			int ret = ipc_call(fd, CMD_DIGEST, req.buf, &resp, &rv);
			json_buf_free(&req);

			if (ret == 0 && rv == CKR_OK && resp != NULL) {
				const char *digest_b64 = json_get_string(resp, "digest");
				if (digest_b64) {
					size_t decoded_len = 0;
					unsigned char *decoded = base64_decode(digest_b64, &decoded_len);
					if (decoded) {
						if (NULL == pDigest) {
							*pulDigestLen = (CK_ULONG)decoded_len;
							free(decoded);
							free(resp);
							return CKR_OK;
						}
						if (*pulDigestLen < (CK_ULONG)decoded_len) {
							*pulDigestLen = (CK_ULONG)decoded_len;
							free(decoded);
							free(resp);
							return CKR_BUFFER_TOO_SMALL;
						}
						memcpy(pDigest, decoded, decoded_len);
						*pulDigestLen = (CK_ULONG)decoded_len;
						pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
						free(decoded);
						free(resp);
						return CKR_OK;
					}
				}
				free(resp);
			}
			if (resp) free(resp);
			if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
		}
	}

	/* IPC 不可用时回退到本地真实摘要计算 */
	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	{
		CK_ULONG hash_size = digest_hash_size(pkcs11_mock_digest_mechanism);
		if (hash_size == 0) return CKR_MECHANISM_INVALID;

		if (NULL == pDigest) {
			*pulDigestLen = hash_size;
			return CKR_OK;
		}
		if (*pulDigestLen < hash_size) {
			*pulDigestLen = hash_size;
			return CKR_BUFFER_TOO_SMALL;
		}

		CK_ULONG out_len = *pulDigestLen;
		int rc = local_digest(pkcs11_mock_digest_mechanism, pData, ulDataLen, pDigest, &out_len);
		if (rc != 0) return CKR_FUNCTION_FAILED;
		*pulDigestLen = out_len;
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	/* 累积数据到摘要缓冲区（本地回退用） */
	if (pkcs11_mock_digest_buf_len + ulPartLen > PKCS11_MOCK_DIGEST_BUF_MAX)
		return CKR_DATA_LEN_RANGE;

	CK_BYTE *new_buf = (CK_BYTE *)realloc(pkcs11_mock_digest_buf, pkcs11_mock_digest_buf_len + ulPartLen);
	if (NULL == new_buf)
		return CKR_HOST_MEMORY;
	memcpy(new_buf + pkcs11_mock_digest_buf_len, pPart, ulPartLen);
	pkcs11_mock_digest_buf = new_buf;
	pkcs11_mock_digest_buf_len += ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		return CKR_OBJECT_HANDLE_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_DIGEST != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	{
		CK_ULONG hash_size = digest_hash_size(pkcs11_mock_digest_mechanism);
		if (hash_size == 0) return CKR_MECHANISM_INVALID;

		if (NULL == pDigest) {
			*pulDigestLen = hash_size;
			return CKR_OK;
		}
		if (*pulDigestLen < hash_size) {
			*pulDigestLen = hash_size;
			return CKR_BUFFER_TOO_SMALL;
		}

		/* 使用累积的数据进行真实摘要计算 */
		CK_ULONG out_len = *pulDigestLen;
		const CK_BYTE *data = pkcs11_mock_digest_buf ? pkcs11_mock_digest_buf : (const CK_BYTE *)"";
		CK_ULONG data_len = pkcs11_mock_digest_buf_len;
		int rc = local_digest(pkcs11_mock_digest_mechanism, data, data_len, pDigest, &out_len);

		/* 释放摘要缓冲区 */
		if (pkcs11_mock_digest_buf) { free(pkcs11_mock_digest_buf); pkcs11_mock_digest_buf = NULL; }
		pkcs11_mock_digest_buf_len = 0;

		if (rc != 0) return CKR_FUNCTION_FAILED;
		*pulDigestLen = out_len;

		switch (pkcs11_mock_active_operation)
		{
			case PKCS11_MOCK_CK_OPERATION_DIGEST:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				break;
			case PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
				break;
			case PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST:
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 SignInit */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"mechanism\":%lu,\"key_handle\":%lu}",
			(unsigned long)hSession,
			(unsigned long)pMechanism->mechanism,
			(unsigned long)hKey);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_SIGN_INIT, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0) {
			if (rv != IPC_CKR_OK) return (CK_RV)rv;
			pkcs11_mock_sign_mechanism = pMechanism->mechanism;
			pkcs11_mock_sign_key = hKey;
			if (PKCS11_MOCK_CK_OPERATION_NONE == pkcs11_mock_active_operation)
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
			else
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT;
			return CKR_OK;
		}
		/* IPC 失败，降级 */
	}

	/* Mock 降级 */
	if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism)) {
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;
		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	} else {
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_sign_mechanism = pMechanism->mechanism;
	pkcs11_mock_sign_key = hKey;

	if (PKCS11_MOCK_CK_OPERATION_NONE == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发签名 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req,
			"{\"session_id\":%lu,\"key_handle\":%lu,\"mechanism\":%lu,\"data\":",
			(unsigned long)hSession,
			(unsigned long)pkcs11_mock_sign_key,
			(unsigned long)pkcs11_mock_sign_mechanism);
		json_buf_append_b64(&req, pData, (size_t)ulDataLen);
		json_buf_append(&req, "}");

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_SIGN, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			uint8_t *sig_data = NULL;
			size_t sig_len = 0;
			if (json_get_b64(resp, "signature", &sig_data, &sig_len) == 0) {
				if (NULL == pSignature) {
					*pulSignatureLen = (CK_ULONG)sig_len;
					free(sig_data);
					free(resp);
					return CKR_OK;
				}
				if (*pulSignatureLen < (CK_ULONG)sig_len) {
					*pulSignatureLen = (CK_ULONG)sig_len;
					free(sig_data);
					free(resp);
					return CKR_BUFFER_TOO_SMALL;
				}
				memcpy(pSignature, sig_data, sig_len);
				*pulSignatureLen = (CK_ULONG)sig_len;
				free(sig_data);
				free(resp);
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				return CKR_OK;
			}
			free(resp);
		}
		if (resp) free(resp);
		/* IPC 失败，降级 */
	}

	/* Mock 降级：返回固定签名 */
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (NULL != pSignature) {
		if (sizeof(signature) > *pulSignatureLen)
			return CKR_BUFFER_TOO_SMALL;
		memcpy(pSignature, signature, sizeof(signature));
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
	}
	*pulSignatureLen = sizeof(signature);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 转发 SignUpdate */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"part\":", (unsigned long)hSession);
		json_buf_append_b64(&req, (const uint8_t *)pPart, (size_t)ulPartLen);
		json_buf_append(&req, "}");

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_SIGN_UPDATE, req.buf, &resp, &rv);
		json_buf_free(&req);
		if (resp) free(resp);

		if (ret == 0 && rv == IPC_CKR_OK) {
			return CKR_OK;
		}
		/* IPC 失败，降级 */
	}

	/* 硬编码降级：接受数据但不做实际处理 */
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_SIGN != pkcs11_mock_active_operation) && 
		(PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	/* 尝试通过 IPC 转发 SignFinal */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu}", (unsigned long)hSession);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_SIGN_FINAL, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == IPC_CKR_OK && resp != NULL) {
			uint8_t *sig_data = NULL;
			size_t sig_len = 0;
			if (json_get_b64(resp, "signature", &sig_data, &sig_len) == 0) {
				if (NULL != pSignature) {
					if (*pulSignatureLen < (CK_ULONG)sig_len) {
						free(sig_data);
						free(resp);
						return CKR_BUFFER_TOO_SMALL;
					}
					memcpy(pSignature, sig_data, sig_len);
					if (PKCS11_MOCK_CK_OPERATION_SIGN == pkcs11_mock_active_operation)
						pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
					else
						pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
				}
				*pulSignatureLen = (CK_ULONG)sig_len;
				free(sig_data);
			}
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		/* IPC 失败，降级到硬编码 */
	}

	/* 硬编码降级 */
	if (NULL != pSignature)
	{
		if (sizeof(signature) > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pSignature, signature, sizeof(signature));

			if (PKCS11_MOCK_CK_OPERATION_SIGN == pkcs11_mock_active_operation)
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
			else
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_ENCRYPT;
		}
	}

	*pulSignatureLen = sizeof(signature);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS == pMechanism->mechanism)
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_SIGN_RECOVER;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN_RECOVER != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (ulDataLen > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulDataLen; i++)
				pSignature[i] = pData[i] ^ 0xAB;

			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulSignatureLen = ulDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT != pkcs11_mock_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	/* 放宽机制白名单：覆盖 RSA/ECDSA/EdDSA 主流验签 */
	switch (pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_ECDSA:
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA_SHA256:
		case CKM_ECDSA_SHA384:
		case CKM_ECDSA_SHA512:
		case CKM_EDDSA:
			if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	if (PKCS11_MOCK_CK_OPERATION_NONE == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY;

	/* 通过 IPC 转发 VerifyInit */
	{
		ipc_fd_t fd = ipc_global_fd();
		if (ipc_is_connected(fd)) {
			json_buf_t req;
			json_buf_init(&req);
			json_buf_appendf(&req, "{\"session_id\":%lu,\"mechanism\":%lu,\"key_handle\":%lu}",
				(unsigned long)hSession, (unsigned long)pMechanism->mechanism, (unsigned long)hKey);

			char *resp = NULL;
			uint32_t rv = 0;
			int ret = ipc_call(fd, CMD_VERIFY_INIT, req.buf, &resp, &rv);
			json_buf_free(&req);
			if (resp) free(resp);

			if (ret == 0 && rv != CKR_OK) {
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				return (CK_RV)rv;
			}
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发验签 */
	{
		ipc_fd_t fd = ipc_global_fd();
		if (ipc_is_connected(fd)) {
			json_buf_t req;
			json_buf_init(&req);
			json_buf_append(&req, "{\"session_id\":");
			json_buf_appendf(&req, "%lu", (unsigned long)hSession);
			json_buf_append(&req, ",\"data\":");
			json_buf_append_b64(&req, pData, (size_t)ulDataLen);
			json_buf_append(&req, ",\"signature\":");
			json_buf_append_b64(&req, pSignature, (size_t)ulSignatureLen);
			json_buf_append(&req, "}");

			char *resp = NULL;
			uint32_t rv = 0;
			int ret = ipc_call(fd, CMD_VERIFY, req.buf, &resp, &rv);
			json_buf_free(&req);
			if (resp) free(resp);

			if (ret == 0) {
				pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				return (CK_RV)rv;
			}
			/* IPC 失败，降级到本地 mock */
		}
	}

	/* 本地 mock 降级：固定签名比对 */
	{
		CK_BYTE mock_sig[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

		if (sizeof(mock_sig) != ulSignatureLen)
			return CKR_SIGNATURE_LEN_RANGE;

		if (0 != memcmp(pSignature, mock_sig, sizeof(mock_sig)))
			return CKR_SIGNATURE_INVALID;
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 VerifyUpdate */
	{
		ipc_fd_t fd = ipc_global_fd();
		if (ipc_is_connected(fd)) {
			json_buf_t req;
			json_buf_init(&req);
			json_buf_append(&req, "{\"session_id\":");
			json_buf_appendf(&req, "%lu", (unsigned long)hSession);
			json_buf_append(&req, ",\"part\":");
			json_buf_append_b64(&req, pPart, (size_t)ulPartLen);
			json_buf_append(&req, "}");

			char *resp = NULL;
			uint32_t rv = 0;
			int ret = ipc_call(fd, CMD_VERIFY_UPDATE, req.buf, &resp, &rv);
			json_buf_free(&req);
			if (resp) free(resp);
			if (ret == 0) return (CK_RV)rv;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_MOCK_CK_OPERATION_VERIFY != pkcs11_mock_active_operation) &&
		(PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 VerifyFinal */
	{
		ipc_fd_t fd = ipc_global_fd();
		if (ipc_is_connected(fd)) {
			json_buf_t req;
			json_buf_init(&req);
			json_buf_append(&req, "{\"session_id\":");
			json_buf_appendf(&req, "%lu", (unsigned long)hSession);
			json_buf_append(&req, ",\"signature\":");
			json_buf_append_b64(&req, pSignature, (size_t)ulSignatureLen);
			json_buf_append(&req, "}");

			char *resp = NULL;
			uint32_t rv = 0;
			int ret = ipc_call(fd, CMD_VERIFY_FINAL, req.buf, &resp, &rv);
			json_buf_free(&req);
			if (resp) free(resp);

			if (ret == 0) {
				if (PKCS11_MOCK_CK_OPERATION_VERIFY == pkcs11_mock_active_operation)
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
				else
					pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;
				return (CK_RV)rv;
			}
		}
	}

	/* 本地 mock 降级：固定签名比对（用于离线开发） */
	{
		CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
		if (sizeof(signature) != ulSignatureLen)
			return CKR_SIGNATURE_LEN_RANGE;
		if (0 != memcmp(pSignature, signature, sizeof(signature)))
			return CKR_SIGNATURE_INVALID;
	}

	if (PKCS11_MOCK_CK_OPERATION_VERIFY == pkcs11_mock_active_operation)
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
	else
		pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_DECRYPT;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_NONE != pkcs11_mock_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS == pMechanism->mechanism)
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_VERIFY_RECOVER;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_VERIFY_RECOVER != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pData)
	{
		if (ulSignatureLen > *pulDataLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulSignatureLen; i++)
				pData[i] = pSignature[i] ^ 0xAB;

			pkcs11_mock_active_operation = PKCS11_MOCK_CK_OPERATION_NONE;
		}
	}

	*pulDataLen = ulSignatureLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT_DIGEST != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_SIGN_ENCRYPT != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_OPERATION_DECRYPT_VERIFY != pkcs11_mock_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_DES3_KEY_GEN != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS_KEY_PAIR_GEN != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (NULL == pPublicKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPublicKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pPrivateKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPrivateKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPublicKey)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPrivateKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (NULL == pPublicKeyTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pPublicKeyTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	for (i = 0; i < ulPrivateKeyAttributeCount; i++)
	{
		if (NULL == pPrivateKeyTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pPrivateKeyTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	/* 通过 IPC 转发密钥对生成 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"mechanism\":%lu}",
			(unsigned long)hSession, (unsigned long)pMechanism->mechanism);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GENERATE_KEY_PAIR, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == CKR_OK && resp != NULL) {
			*phPublicKey = (CK_OBJECT_HANDLE)json_get_int(resp, "pub_handle",
				PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY);
			*phPrivateKey = (CK_OBJECT_HANDLE)json_get_int(resp, "priv_handle",
				PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY);
			free(resp);
			return CKR_OK;
		}
		if (resp) free(resp);
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	/* IPC 不可用时回退到硬编码值 */
	*phPublicKey = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
	*phPrivateKey = PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_BYTE wrappedKey[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hWrappingKey)
		return CKR_KEY_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		return CKR_KEY_HANDLE_INVALID;

	if (NULL != pWrappedKey)
	{
		if (sizeof(wrappedKey) > *pulWrappedKeyLen)
			return CKR_BUFFER_TOO_SMALL;
		else
			memcpy(pWrappedKey, wrappedKey, sizeof(wrappedKey));
	}

	*pulWrappedKeyLen = sizeof(wrappedKey);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hUnwrappingKey)
		return CKR_KEY_HANDLE_INVALID;

	if (NULL == pWrappedKey)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulWrappedKeyLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulAttributeCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_XOR_BASE_AND_DATA != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL == pMechanism->pParameter) || (sizeof(CK_KEY_DERIVATION_STRING_DATA) != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hBaseKey)
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	if ((NULL != pTemplate) && (0 < ulAttributeCount))
	{
		for (i = 0; i < ulAttributeCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSeed)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSeedLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发，让 client-card 记录种子数据（标准库 CSPRNG 不可手动 seed） */
	{
		ipc_fd_t fd = ipc_global_fd();
		if (ipc_is_connected(fd)) {
			char *seed_b64 = base64_encode(pSeed, ulSeedLen);
			if (seed_b64) {
				json_buf_t req;
				json_buf_init(&req);
				json_buf_appendf(&req, "{\"session_id\":%lu,\"seed\":\"%s\"}",
					(unsigned long)hSession, seed_b64);
				free(seed_b64);

				char *resp = NULL;
				uint32_t rv = 0;
				int ret = ipc_call(fd, CMD_SEED_RANDOM, req.buf, &resp, &rv);
				json_buf_free(&req);
				if (resp) free(resp);
				if (ret == 0) return (CK_RV)rv;
			}
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == RandomData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulRandomLen)
		return CKR_ARGUMENTS_BAD;

	/* 通过 IPC 转发 */
	ipc_fd_t fd = ipc_global_fd();
	if (ipc_is_connected(fd)) {
		json_buf_t req;
		json_buf_init(&req);
		json_buf_appendf(&req, "{\"session_id\":%lu,\"length\":%lu}",
			(unsigned long)hSession, (unsigned long)ulRandomLen);

		char *resp = NULL;
		uint32_t rv = 0;
		int ret = ipc_call(fd, CMD_GENERATE_RANDOM, req.buf, &resp, &rv);
		json_buf_free(&req);

		if (ret == 0 && rv == CKR_OK && resp != NULL) {
			/* 解析 Base64 编码的随机数据 */
			const char *data_b64 = json_get_string(resp, "data");
			if (data_b64) {
				size_t decoded_len = 0;
				unsigned char *decoded = base64_decode(data_b64, &decoded_len);
				if (decoded && decoded_len >= ulRandomLen) {
					memcpy(RandomData, decoded, ulRandomLen);
					free(decoded);
					free(resp);
					return CKR_OK;
				}
				if (decoded) free(decoded);
			}
			free(resp);
		}
		if (resp) free(resp);
		if (ret == 0 && rv != CKR_OK) return (CK_RV)rv;
	}

	/* IPC 不可用时回退到本地 CSPRNG */
	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

#ifdef _WIN32
	{
		HCRYPTPROV hProv = 0;
		if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
			BOOL ok = CryptGenRandom(hProv, (DWORD)ulRandomLen, (BYTE *)RandomData);
			CryptReleaseContext(hProv, 0);
			if (ok) return CKR_OK;
		}
		return CKR_DEVICE_ERROR;
	}
#else
	{
		FILE *f = fopen("/dev/urandom", "rb");
		if (NULL == f) return CKR_DEVICE_ERROR;
		size_t got = fread(RandomData, 1, (size_t)ulRandomLen, f);
		fclose(f);
		return (got == (size_t)ulRandomLen) ? CKR_OK : CKR_DEVICE_ERROR;
	}
#endif
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;
	
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;
	
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((0 != flags)  && (CKF_DONT_BLOCK != flags))
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSlot)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pReserved)
		return CKR_ARGUMENTS_BAD;

	return CKR_NO_EVENT;
}


/* #region PKCS11-MOCK vendor defined functions */


CK_DEFINE_FUNCTION(CK_RV, C_GetUnmanagedStructSizeList)(CK_ULONG_PTR pSizeList, CK_ULONG_PTR pulCount)
{
	CK_ULONG sizes[] = {
		sizeof(CK_ATTRIBUTE),
		sizeof(CK_C_INITIALIZE_ARGS),
		sizeof(CK_FUNCTION_LIST),
		sizeof(CK_INFO),
		sizeof(CK_MECHANISM),
		sizeof(CK_MECHANISM_INFO),
		sizeof(CK_SESSION_INFO),
		sizeof(CK_SLOT_INFO),
		sizeof(CK_TOKEN_INFO),
		sizeof(CK_VERSION),
		sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_AES_CTR_PARAMS),
		sizeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_CAMELLIA_CTR_PARAMS),
		sizeof(CK_CMS_SIG_PARAMS),
		sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS),
		sizeof(CK_ECDH1_DERIVE_PARAMS),
		sizeof(CK_ECDH2_DERIVE_PARAMS),
		sizeof(CK_ECMQV_DERIVE_PARAMS),
		sizeof(CK_EXTRACT_PARAMS),
		sizeof(CK_KEA_DERIVE_PARAMS),
		sizeof(CK_KEY_DERIVATION_STRING_DATA),
		sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS),
		sizeof(CK_KIP_PARAMS),
		sizeof(CK_MAC_GENERAL_PARAMS),
		sizeof(CK_OTP_PARAM),
		sizeof(CK_OTP_PARAMS),
		sizeof(CK_OTP_SIGNATURE_INFO),
		sizeof(CK_PBE_PARAMS),
		sizeof(CK_PKCS5_PBKD2_PARAMS),
		sizeof(CK_RC2_CBC_PARAMS),
		sizeof(CK_RC2_MAC_GENERAL_PARAMS),
		sizeof(CK_RC2_PARAMS),
		sizeof(CK_RC5_CBC_PARAMS),
		sizeof(CK_RC5_MAC_GENERAL_PARAMS),
		sizeof(CK_RC5_PARAMS),
		sizeof(CK_RSA_PKCS_OAEP_PARAMS),
		sizeof(CK_RSA_PKCS_PSS_PARAMS),
		sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS),
		sizeof(CK_SKIPJACK_RELAYX_PARAMS),
		sizeof(CK_SSL3_KEY_MAT_OUT),
		sizeof(CK_SSL3_KEY_MAT_PARAMS),
		sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS),
		sizeof(CK_SSL3_RANDOM_DATA),
		sizeof(CK_TLS_PRF_PARAMS),
		sizeof(CK_WTLS_KEY_MAT_OUT),
		sizeof(CK_WTLS_KEY_MAT_PARAMS),
		sizeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS),
		sizeof(CK_WTLS_PRF_PARAMS),
		sizeof(CK_WTLS_RANDOM_DATA),
		sizeof(CK_X9_42_DH1_DERIVE_PARAMS),
		sizeof(CK_X9_42_DH2_DERIVE_PARAMS),
		sizeof(CK_X9_42_MQV_DERIVE_PARAMS),
	};

	CK_ULONG sizes_count = sizeof(sizes) / sizeof(CK_ULONG);

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSizeList)
	{
		*pulCount = sizes_count;
	}
	else
	{
		if (sizes_count > *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		memcpy(pSizeList, sizes, sizeof(sizes));
		*pulCount = sizes_count;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EjectToken)(CK_SLOT_ID slotID)
{
	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_MOCK_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InteractiveLogin)(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;

	if (CK_FALSE == pkcs11_mock_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_mock_session_opened) || (PKCS11_MOCK_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	switch (pkcs11_mock_session_state)
	{
		case CKS_RO_PUBLIC_SESSION:

			pkcs11_mock_session_state = CKS_RO_USER_FUNCTIONS;

			break;

		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:

			rv = CKR_USER_ALREADY_LOGGED_IN;

			break;

		case CKS_RW_PUBLIC_SESSION:

			pkcs11_mock_session_state = CKS_RW_USER_FUNCTIONS;

			break;

		case CKS_RW_SO_FUNCTIONS:

			rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

			break;
	}

	return rv;
}


/* #endregion PKCS11-MOCK vendor defined functions */


/* #region PKCS#11 v3.1 functions */


CK_DEFINE_FUNCTION(CK_RV, C_GetInterfaceList)(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pInterfacesList)
	{
		*pulCount = 2;
	}
	else
	{
		if (*pulCount < 2)
			return CKR_BUFFER_TOO_SMALL;

		pInterfacesList[0].pInterfaceName = pkcs11_mock_2_40_interface.pInterfaceName;
		pInterfacesList[0].pFunctionList = pkcs11_mock_2_40_interface.pFunctionList;
		pInterfacesList[0].flags = pkcs11_mock_2_40_interface.flags;

		pInterfacesList[1].pInterfaceName = pkcs11_mock_3_1_interface.pInterfaceName;
		pInterfacesList[1].pFunctionList = pkcs11_mock_3_1_interface.pFunctionList;
		pInterfacesList[1].flags = pkcs11_mock_3_1_interface.flags;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterface)(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion, CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	if (NULL == ppInterface)
		return CKR_ARGUMENTS_BAD;

	if (flags != 0)
	{
		*ppInterface = NULL;
		return CKR_OK;
	}

	if (NULL != pInterfaceName)
	{
		const char* requested_interface_name = (const char*)pInterfaceName;
		const char* supported_interface_name = "PKCS 11";

		if (strlen(requested_interface_name) != strlen(supported_interface_name) || 0 != strcmp(requested_interface_name, supported_interface_name))
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	if (NULL != pVersion)
	{
		if (pVersion->major == pkcs11_mock_2_40_functions.version.major && pVersion->minor == pkcs11_mock_2_40_functions.version.minor)
		{
			*ppInterface = &pkcs11_mock_2_40_interface;
			return CKR_OK;
		}
		else if (pVersion->major == pkcs11_mock_3_1_functions.version.major && pVersion->minor == pkcs11_mock_3_1_functions.version.minor)
		{
			*ppInterface = &pkcs11_mock_3_1_interface;
			return CKR_OK;
		}
		else
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	*ppInterface = &pkcs11_mock_3_1_interface;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_LoginUser)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	UNUSED(hSession);
	UNUSED(userType);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pUsername);
	UNUSED(ulUsernameLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SessionCancel)(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pPlaintext);
	UNUSED(ulPlaintextLen);
	UNUSED(pCiphertext);
	UNUSED(pulCiphertextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pPlaintextPart);
	UNUSED(ulPlaintextPartLen);
	UNUSED(pCiphertextPart);
	UNUSED(pulCiphertextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pCiphertext);
	UNUSED(ulCiphertextLen);
	UNUSED(pPlaintext);
	UNUSED(pulPlaintextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pCiphertextPart);
	UNUSED(ulCiphertextPartLen);
	UNUSED(pPlaintextPart);
	UNUSED(pulPlaintextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* #endregion PKCS#11 v3.1 functions */