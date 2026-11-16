package fido

import "encoding/base64"

// BuildGetInfo 构造 CTAP2 GetInfo 响应的 CBOR（固定能力集，P0 不支持 clientPIN）。
//
// 手工编码，避免为单个固定结构引入 CBOR 依赖。
func BuildGetInfo() []byte {
	out := []byte{0xA5}                 // map(5)
	out = append(out, 0x01, 0x81, 0x68) // 1: ["FIDO_2_0"]
	out = append(out, []byte("FIDO_2_0")...)
	out = append(out, 0x03, 0x50) // 3: aaguid(16)
	out = append(out, make([]byte, 16)...)
	out = append(out, 0x04, 0xA4) // 4: options
	out = append(out, 0x62)
	out = append(out, []byte("rk")...)
	out = append(out, 0xF5)
	out = append(out, 0x62)
	out = append(out, []byte("up")...)
	out = append(out, 0xF5)
	out = append(out, 0x69)
	out = append(out, []byte("clientPin")...)
	out = append(out, 0xF4)
	out = append(out, 0x64)
	out = append(out, []byte("plat")...)
	out = append(out, 0xF4)
	out = append(out, 0x05, 0x19, 0x04, 0xB0) // 5: maxMsgSize 1200
	out = append(out, 0x07, 0x81, 0x01)       // 7: pinProtocols [1]
	return out
}

// GetInfoResponse 返回参考项目约定的 IPC 响应结构。
func GetInfoResponse() map[string]any {
	return map[string]any{
		"rv": 0,
		"data": map[string]string{
			"cbor_info": base64.StdEncoding.EncodeToString(BuildGetInfo()),
		},
	}
}
