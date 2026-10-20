package meta

// AlgorithmInfo 描述一个密码学算法条目。
type AlgorithmInfo struct {
	Name        string `json:"name"`        // 算法标识（如 "ec256"、"sm2"）
	Display     string `json:"display"`     // 中文显示名
	Category    string `json:"category"`    // 分类：key / hash / cipher / signature
	Available   bool   `json:"available"`   // 当前构建下是否可用（SM 系列受 build tag 影响）
	Deprecated  bool   `json:"deprecated"`  // 是否已弃用（如 MD5、SHA1 不推荐）
	Description string `json:"description"` // 补充说明
}

// supportedAlgorithms 返回当前已知的密码学算法清单。
// SM2/SM3/SM4 的 Available 由运行时 sm2Available()（在 ca 包）查询；
// 此处给出默认视图，Server 层可按实际构建覆盖 Available 字段。
var supportedAlgorithms = []AlgorithmInfo{
	// ---- 非对称密钥 ----
	{Name: "rsa1024", Display: "RSA 1024", Category: "key", Available: true, Deprecated: true, Description: "不推荐新颁发"},
	{Name: "rsa2048", Display: "RSA 2048", Category: "key", Available: true},
	{Name: "rsa3072", Display: "RSA 3072", Category: "key", Available: true},
	{Name: "rsa4096", Display: "RSA 4096", Category: "key", Available: true},
	{Name: "rsa8192", Display: "RSA 8192", Category: "key", Available: true, Description: "性能较差，仅用于长期根 CA"},
	{Name: "ec256", Display: "ECDSA P-256", Category: "key", Available: true},
	{Name: "ec384", Display: "ECDSA P-384", Category: "key", Available: true},
	{Name: "ec521", Display: "ECDSA P-521", Category: "key", Available: true},
	{Name: "ed25519", Display: "Ed25519", Category: "key", Available: true},
	{Name: "x25519", Display: "X25519 (ECDH)", Category: "key", Available: true, Description: "仅用于密钥交换"},
	{Name: "brainpoolP256r1", Display: "Brainpool P-256r1", Category: "key", Available: false, Description: "需启用 brainpool tag"},
	{Name: "brainpoolP384r1", Display: "Brainpool P-384r1", Category: "key", Available: false, Description: "需启用 brainpool tag"},
	{Name: "brainpoolP512r1", Display: "Brainpool P-512r1", Category: "key", Available: false, Description: "需启用 brainpool tag"},
	{Name: "sm2", Display: "SM2 (国密)", Category: "key", Available: true},

	// ---- 哈希算法 ----
	{Name: "md5", Display: "MD5", Category: "hash", Available: true, Deprecated: true, Description: "已被证实存在碰撞攻击"},
	{Name: "sha1", Display: "SHA-1", Category: "hash", Available: true, Deprecated: true, Description: "浏览器已停止信任"},
	{Name: "sha256", Display: "SHA-256", Category: "hash", Available: true},
	{Name: "sha384", Display: "SHA-384", Category: "hash", Available: true},
	{Name: "sha512", Display: "SHA-512", Category: "hash", Available: true},
	{Name: "sha3-256", Display: "SHA3-256", Category: "hash", Available: true},
	{Name: "sha3-384", Display: "SHA3-384", Category: "hash", Available: true},
	{Name: "sha3-512", Display: "SHA3-512", Category: "hash", Available: true},
	{Name: "sm3", Display: "SM3 (国密)", Category: "hash", Available: true},

	// ---- 对称加密算法 ----
	{Name: "aes128", Display: "AES-128", Category: "cipher", Available: true},
	{Name: "aes192", Display: "AES-192", Category: "cipher", Available: true},
	{Name: "aes256", Display: "AES-256", Category: "cipher", Available: true},
	{Name: "chacha20", Display: "ChaCha20-Poly1305", Category: "cipher", Available: true},
	{Name: "sm4", Display: "SM4 (国密)", Category: "cipher", Available: true},
}

// SignatureAlgorithmInfo 描述一个证书签名算法条目（名称与可读展示）。
type SignatureAlgorithmInfo struct {
	Name    string `json:"name"`    // 传给 ca.IssueRequest.SignatureAlgorithm 的标识
	Display string `json:"display"` // 中文显示名
	Hash    string `json:"hash"`    // 对应摘要算法（展示用）
}

// SignatureAlgorithms 是系统支持的证书签名算法清单。
var SignatureAlgorithms = []SignatureAlgorithmInfo{
	{Name: "SHA256_RSA", Display: "RSA + SHA-256", Hash: "sha256"},
	{Name: "SHA384_RSA", Display: "RSA + SHA-384", Hash: "sha384"},
	{Name: "SHA512_RSA", Display: "RSA + SHA-512", Hash: "sha512"},
	{Name: "SHA256_RSA_PSS", Display: "RSA-PSS + SHA-256", Hash: "sha256"},
	{Name: "SHA384_RSA_PSS", Display: "RSA-PSS + SHA-384", Hash: "sha384"},
	{Name: "SHA512_RSA_PSS", Display: "RSA-PSS + SHA-512", Hash: "sha512"},
	{Name: "ECDSA_SHA256", Display: "ECDSA + SHA-256", Hash: "sha256"},
	{Name: "ECDSA_SHA384", Display: "ECDSA + SHA-384", Hash: "sha384"},
	{Name: "ECDSA_SHA512", Display: "ECDSA + SHA-512", Hash: "sha512"},
	{Name: "ED25519", Display: "Ed25519", Hash: "内置"},
	{Name: "SM2WithSM3", Display: "SM2 + SM3", Hash: "sm3"},
}

// KeyTypeToSigHashes 是"密钥算法 → 允许的签名哈希"映射，前端据此联动：
// 选择 RSA/ECDSA 时提供常规哈希选项；选择 SM2 时只能选 SM3；
// Ed25519 没有独立哈希选择（算法内置）。
var KeyTypeToSigHashes = map[string][]string{
	"rsa1024": {"sha256", "sha384", "sha512"},
	"rsa2048": {"sha256", "sha384", "sha512"},
	"rsa3072": {"sha256", "sha384", "sha512"},
	"rsa4096": {"sha256", "sha384", "sha512"},
	"rsa8192": {"sha256", "sha384", "sha512"},
	"ec256":   {"sha256", "sha384", "sha512"},
	"ec384":   {"sha256", "sha384", "sha512"},
	"ec521":   {"sha256", "sha384", "sha512"},
	"ed25519": {},
	"sm2":     {"sm3"},
}

// GetSupportedAlgorithms 返回全部算法。
// availabilityOverrides 可按算法名覆盖 Available 字段（便于 Server 层注入运行时判定，如 SM2 是否已编译）。
func GetSupportedAlgorithms(availabilityOverrides map[string]bool) []AlgorithmInfo {
	out := make([]AlgorithmInfo, len(supportedAlgorithms))
	copy(out, supportedAlgorithms)
	if availabilityOverrides != nil {
		for i := range out {
			if v, ok := availabilityOverrides[out[i].Name]; ok {
				out[i].Available = v
			}
		}
	}
	return out
}
