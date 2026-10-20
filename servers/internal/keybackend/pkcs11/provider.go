package pkcs11

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/globaltrusts/server-card/internal/keybackend"
)

func init() {
	keybackend.Register(keybackend.Descriptor{
		Driver:      keybackend.DriverPKCS11,
		Kind:        keybackend.KindHSM,
		Name:        "PKCS#11 硬件安全模块 / USB 令牌",
		Description: "通过标准 PKCS#11 接口对接任意厂商模块：SafeNet eToken 5110（eTPKCS11.dll）、SoftHSM2、网络 HSM、YubiKey PIV 等。私钥在设备内生成与使用，不离开硬件。",
		Fields: []keybackend.Field{
			{Key: "library", Label: "PKCS#11 模块路径", Type: keybackend.FieldFile, Required: true,
				Hint: "例如 C:\\Windows\\System32\\eTPKCS11.dll（eToken 5110）、/usr/lib/softhsm/libsofthsm2.so（SoftHSM2）。可先点击「扫描本机模块」自动发现。"},
			{Key: "token", Label: "令牌标识（标签或序列号）", Type: keybackend.FieldText,
				Hint: "多设备场景用于精确定位；留空时按槽位序号选择。"},
			{Key: "slot", Label: "槽位序号", Type: keybackend.FieldNumber, Default: "0",
				Hint: "从 0 开始；令牌标识为空时生效。"},
			{Key: "pin", Label: "用户 PIN", Type: keybackend.FieldPassword, Required: true, Secret: true,
				Hint: "用于登录令牌。服务端加密保存，不会回显。"},
			{Key: "keygen", Label: "允许在设备内生成密钥", Type: keybackend.FieldBool, Default: "true",
				Hint: "推荐开启：私钥始终留在硬件内，安全等级最高。"},
			{Key: "import", Label: "允许导入外部私钥", Type: keybackend.FieldBool, Default: "false",
				Hint: "仅在确实需要把外部私钥写入设备时开启；部分令牌不支持导入。"},
			{Key: "label_prefix", Label: "对象标签前缀", Type: keybackend.FieldText, Default: "opencert/",
				Hint: "写入设备对象的 CKA_LABEL 前缀，便于运维识别。"},
		},
		Presets: defaultPresets(),
		Capabilities: keybackend.Capabilities{
			Generate:   true,
			Import:     true,
			Sign:       true,
			Decrypt:    true,
			Exportable: false,
			Persistent: true,
			KeyTypes:   []string{"rsa1024", "rsa2048", "rsa3072", "rsa4096", "ec256", "ec384", "ec521"},
			SignSchemes: []string{
				"MD5_RSA_PKCS", "SHA1_RSA_PKCS", "SHA256_RSA_PKCS", "SHA384_RSA_PKCS", "SHA512_RSA_PKCS",
				"SHA256_RSA_PSS", "SHA384_RSA_PSS", "SHA512_RSA_PSS",
				"ECDSA", "ECDSA_SHA1", "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512",
			},
			Note: "实际可用的算法与机制取决于所选设备；Ed25519 通常不被支持",
		},
		Available:       runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64",
		AvailableDetail: "支持任意厂商的 64 位 PKCS#11 v2.x 模块（无需 cgo）",
		Factory:         newProvider,
	})
}

// keyRef 是写入 certificates.key_ref 的 PKCS#11 私钥引用。
type keyRef struct {
	Library   string `json:"library"`
	Token     string `json:"token"` // 令牌序列号或标签（优先序列号）
	SlotIndex int    `json:"slot_index"`
	CKAID     string `json:"cka_id"` // CKA_ID（十六进制）
	KeyType   string `json:"key_type"`
	Label     string `json:"label"`
	PublicDER string `json:"public_der,omitempty"` // 公钥 SPKI（base64，便于离线排障）
	Model     string `json:"model,omitempty"`
}

type provider struct {
	params keybackend.Params
	label  string

	library     string
	prefix      string
	allowGen    bool
	allowImport bool

	mu      sync.Mutex
	module  *Module
	session *Session
	slotID  ckULong
	slotIdx int
	token   string
	model   string
	serial  string
	closed  bool

	// sessionMu 串行化设备操作（PKCS#11 会话非线程安全）。
	sessionMu sync.Mutex
}

func newProvider(_ context.Context, cfg keybackend.Config) (keybackend.Provider, error) {
	library := keybackend.ExpandPath(cfg.Params.Get("library"))
	if library == "" {
		return nil, fmt.Errorf("%w: 未配置 PKCS#11 模块路径", keybackend.ErrBadConfig)
	}
	if _, err := os.Stat(library); err != nil {
		return nil, fmt.Errorf("%w: PKCS#11 模块不存在（%s）", keybackend.ErrBadConfig, library)
	}
	return &provider{
		params:      cfg.Params,
		label:       cfg.Label,
		library:     library,
		prefix:      cfg.Params.GetDefault("label_prefix", "opencert/"),
		allowGen:    !cfg.Params.Has("keygen") || cfg.Params.Bool("keygen"),
		allowImport: cfg.Params.Bool("import"),
	}, nil
}

func (p *provider) Driver() string { return keybackend.DriverPKCS11 }
func (p *provider) Kind() keybackend.Kind {
	return keybackend.KindHSM
}

func (p *provider) Capabilities() keybackend.Capabilities {
	caps := keybackend.Capabilities{
		Generate:   p.allowGen,
		Import:     p.allowImport,
		Sign:       true,
		Decrypt:    true,
		Exportable: false,
		Persistent: true,
		KeyTypes:   []string{"rsa1024", "rsa2048", "rsa3072", "rsa4096", "ec256", "ec384", "ec521"},
		SignSchemes: []string{
			"MD5_RSA_PKCS", "SHA1_RSA_PKCS", "SHA256_RSA_PKCS", "SHA384_RSA_PKCS", "SHA512_RSA_PKCS",
			"SHA256_RSA_PSS", "SHA384_RSA_PSS", "SHA512_RSA_PSS",
			"ECDSA", "ECDSA_SHA1", "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512",
		},
		Note: "算法可用性取决于所选设备；私钥不可导出",
	}
	return caps
}

func (p *provider) Info(_ context.Context) (*keybackend.Info, error) {
	info := &keybackend.Info{Driver: keybackend.DriverPKCS11, Kind: keybackend.KindHSM}
	module, err := p.ensureModule()
	if err != nil {
		info.OK = false
		info.Detail = err.Error()
		return info, nil
	}
	libInfo, _ := module.LibraryInfo()
	slots, err := module.ListSlots()
	if err != nil {
		info.OK = false
		info.Detail = "枚举槽位失败: " + err.Error()
		return info, nil
	}
	for _, s := range slots {
		if !s.TokenPresent {
			continue
		}
		info.Devices = append(info.Devices, keybackend.DeviceInfo{
			Name:      s.Token.Label,
			Model:     s.Token.Model,
			Serial:    s.Token.Serial,
			SlotID:    uint64(s.ID),
			SlotIndex: s.Index,
		})
	}
	if len(info.Devices) == 0 {
		info.OK = false
		info.Detail = "模块可用，但未检测到已插入的令牌"
		return info, nil
	}
	// 尝试建立会话并登录，验证 PIN 是否正确（与设备操作串行，避免会话竞争）
	if serr := p.openSessionLocked(); serr != nil {
		info.OK = false
		info.Detail = serr.Error()
	} else {
		info.Detail = fmt.Sprintf("模块 %s v%d.%d（%s），已登录令牌 %s",
			strings.TrimSpace(libInfo.Description), libInfo.LibraryMajor, libInfo.LibraryMinor,
			module.LayoutNote(), p.token)
		info.OK = true
	}
	return info, nil
}

func (p *provider) Generate(ctx context.Context, spec keybackend.KeySpec) (*keybackend.KeyPair, error) {
	if !p.allowGen {
		return nil, fmt.Errorf("%w: 该存储区域未开启「设备内生成密钥」", keybackend.ErrNotSupported)
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	label := p.prefix + shortLabel(spec.Label, id)
	gen, err := runOnSession(p, func(s *Session) (*GeneratedKey, error) {
		return s.GenerateKeyPair(KeyGenRequest{
			KeyType:     spec.KeyType,
			Label:       label,
			ID:          id,
			Extractable: false,
		})
	})
	if err != nil {
		return nil, err
	}
	ref := keyRef{
		Library:   p.library,
		Token:     p.token,
		SlotIndex: p.slotIdx,
		CKAID:     hex.EncodeToString(id),
		KeyType:   spec.KeyType,
		Label:     label,
		PublicDER: base64.StdEncoding.EncodeToString(gen.PublicDER),
		Model:     p.model,
	}
	refStr, err := keybackend.EncodeRef(keybackend.DriverPKCS11, ref)
	if err != nil {
		return nil, err
	}
	slog.Info("[PKCS#11] 已在设备内生成密钥对",
		"token", p.token, "label", label, "key_type", spec.KeyType)
	return &keybackend.KeyPair{
		PublicDER: gen.PublicDER,
		Ref:       refStr,
		Driver:    keybackend.DriverPKCS11,
		Hardware:  true,
	}, nil
}

func (p *provider) Import(ctx context.Context, privDER []byte, spec keybackend.KeySpec) (*keybackend.KeyPair, error) {
	if !p.allowImport {
		return nil, fmt.Errorf("%w: 该存储区域未开启「导入外部私钥」", keybackend.ErrNotSupported)
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	label := p.prefix + shortLabel(spec.Label, id)
	type result struct {
		gen     *GeneratedKey
		warning string
	}
	res, err := runOnSession(p, func(s *Session) (*result, error) {
		gen, warn, err := s.ImportPrivateKey(ImportPrivateKeyRequest{
			PrivDER: privDER,
			KeyType: spec.KeyType,
			Label:   label,
			ID:      id,
		})
		if err != nil {
			return nil, err
		}
		return &result{gen: gen, warning: warn}, nil
	})
	if err != nil {
		return nil, err
	}
	ref := keyRef{
		Library:   p.library,
		Token:     p.token,
		SlotIndex: p.slotIdx,
		CKAID:     hex.EncodeToString(id),
		KeyType:   spec.KeyType,
		Label:     label,
		PublicDER: base64.StdEncoding.EncodeToString(res.gen.PublicDER),
		Model:     p.model,
	}
	refStr, err := keybackend.EncodeRef(keybackend.DriverPKCS11, ref)
	if err != nil {
		return nil, err
	}
	return &keybackend.KeyPair{
		PublicDER: res.gen.PublicDER,
		Ref:       refStr,
		Driver:    keybackend.DriverPKCS11,
		Hardware:  true,
		Warning:   res.warning,
	}, nil
}

func (p *provider) Sign(_ context.Context, key keybackend.KeyHandle, mechanism string, data []byte) ([]byte, error) {
	ref, err := decodeRef(key.Ref)
	if err != nil {
		return nil, err
	}
	l, err := p.structLayout()
	if err != nil {
		return nil, err
	}
	req, err := buildSignRequest(l, mechanism, ref.KeyType, data)
	if err != nil {
		return nil, err
	}
	sig, err := runOnSession(p, func(s *Session) ([]byte, error) {
		h, err := s.findPrivateKey(ref)
		if err != nil {
			return nil, err
		}
		out, signErr := s.Sign(h, req.mech, req.input)
		runtime.KeepAlive(req)
		return out, signErr
	})
	runtime.KeepAlive(req)
	return sig, err
}

func (p *provider) Decrypt(_ context.Context, key keybackend.KeyHandle, mechanism string, ciphertext []byte) ([]byte, error) {
	ref, err := decodeRef(key.Ref)
	if err != nil {
		return nil, err
	}
	if normalKeyType(ref.KeyType) != "rsa" {
		return nil, fmt.Errorf("解密仅支持 RSA 私钥（当前为 %s）", ref.KeyType)
	}
	l, err := p.structLayout()
	if err != nil {
		return nil, err
	}
	req, err := buildDecryptMechanism(l, mechanism)
	if err != nil {
		return nil, err
	}
	out, err := runOnSession(p, func(s *Session) ([]byte, error) {
		h, err := s.findPrivateKey(ref)
		if err != nil {
			return nil, err
		}
		plain, decErr := s.Decrypt(h, req.mech, ciphertext)
		runtime.KeepAlive(req)
		return plain, decErr
	})
	runtime.KeepAlive(req)
	return out, err
}

// Export 尝试导出私钥。设备内生成的密钥恒为 CKA_EXTRACTABLE=false，
// 读取 CKA_VALUE 会返回 CKR_ATTRIBUTE_SENSITIVE，此时返回 ErrNotExportable。
func (p *provider) Export(_ context.Context, key keybackend.KeyHandle) ([]byte, error) {
	ref, err := decodeRef(key.Ref)
	if err != nil {
		return nil, err
	}
	der, err := runOnSession(p, func(s *Session) ([]byte, error) {
		h, err := s.findPrivateKey(ref)
		if err != nil {
			return nil, err
		}
		return s.Attribute(h, ckaValue)
	})
	if err != nil || len(der) == 0 {
		return nil, keybackend.ErrNotExportable
	}
	// PKCS#11 的 CKA_VALUE 是裸私钥字节，转成 PKCS#8 供上层统一使用
	priv, perr := keybackend.ParsePrivateKey(der)
	if perr != nil {
		return nil, fmt.Errorf("设备导出的私钥无法解析为 PKCS#8: %w", perr)
	}
	return keybackend.MarshalPKCS8(priv)
}

func (p *provider) Destroy(_ context.Context, key keybackend.KeyHandle) error {
	ref, err := decodeRef(key.Ref)
	if err != nil {
		return err
	}
	_, err = runOnSession(p, func(s *Session) (struct{}, error) {
		id, derr := hex.DecodeString(ref.CKAID)
		if derr != nil {
			return struct{}{}, fmt.Errorf("私钥引用中的 CKA_ID 非法: %w", derr)
		}
		handles, ferr := s.FindObjects(newAttrBuffer(s.m.layout).add(ckaID, id), 8)
		if ferr != nil {
			return struct{}{}, ferr
		}
		var lastErr error
		for _, h := range handles {
			if derr := s.DestroyObject(h); derr != nil {
				lastErr = derr
			}
		}
		return struct{}{}, lastErr
	})
	return err
}

func (p *provider) Close() error {
	// 先独占会话锁，确保没有正在进行的设备操作
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.session != nil {
		_ = p.session.Close()
		p.session = nil
	}
	if p.module != nil {
		ReleaseModule(p.module.Path())
		p.module = nil
	}
	return nil
}

// ---- 内部实现 ----

// structLayout 返回模块的结构体布局（必要时先加载模块）。
func (p *provider) structLayout() (layout, error) {
	m, err := p.ensureModule()
	if err != nil {
		return layout{}, err
	}
	return m.layout, nil
}

func (p *provider) ensureModule() (*Module, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, fmt.Errorf("PKCS#11 后端已关闭")
	}
	if p.module != nil {
		return p.module, nil
	}
	m, err := LoadModule(p.library)
	if err != nil {
		return nil, err
	}
	p.module = m
	return m, nil
}

func (p *provider) ensureSession() (*Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, fmt.Errorf("PKCS#11 后端已关闭")
	}
	if p.session != nil && !p.session.closed {
		return p.session, nil
	}
	if p.module == nil {
		return nil, fmt.Errorf("PKCS#11 模块尚未加载")
	}
	slot, err := p.pickSlotLocked()
	if err != nil {
		return nil, err
	}
	pin := p.params.Get("pin")
	s, err := p.module.OpenSession(slot.ID, pin, slot.Token.LoginRequired)
	if err != nil {
		return nil, err
	}
	p.session = s
	p.slotID = slot.ID
	p.slotIdx = slot.Index
	if slot.Token.Serial != "" {
		p.token = slot.Token.Serial
	} else {
		p.token = slot.Token.Label
	}
	p.model = slot.Token.Model
	p.serial = slot.Token.Serial
	slog.Info("[PKCS#11] 已打开会话", "module", p.library, "token", p.token, "slot", slot.Index)
	return s, nil
}

// pickSlotLocked 按配置选择槽位（调用方需持有锁）。
func (p *provider) pickSlotLocked() (*Slot, error) {
	slots, err := p.module.ListSlots()
	if err != nil {
		return nil, err
	}
	if len(slots) == 0 {
		return nil, fmt.Errorf("PKCS#11 模块未返回任何槽位")
	}
	want := p.params.Get("token")
	if want != "" {
		for i := range slots {
			s := &slots[i]
			if !s.TokenPresent {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(s.Token.Label), want) ||
				strings.EqualFold(strings.TrimSpace(s.Token.Serial), want) {
				return s, nil
			}
		}
		return nil, fmt.Errorf("未找到令牌 %q（请确认设备已插入，或核对标签/序列号）", want)
	}
	idx := p.params.Int("slot", 0)
	// 优先在「有令牌」的槽位中按序号选择
	var present []Slot
	for _, s := range slots {
		if s.TokenPresent {
			present = append(present, s)
		}
	}
	if len(present) == 0 {
		return nil, fmt.Errorf("未检测到已插入的令牌（请插入 eToken/HSM 后重试）")
	}
	if idx < 0 || idx >= len(present) {
		return &present[0], nil
	}
	return &present[idx], nil
}

// runOnSession 在会话上串行执行操作。
//
// PKCS#11 的会话不是线程安全的：C_SignInit/C_Sign、C_DecryptInit/C_Decrypt 必须成对且不可交叉，
// 因此这里用互斥锁把「设备操作」串行化（同一张卡片的并发签名会排队执行）。
// 遇到会话失效（拔卡、超时、被其它进程踢出）时自动重建会话并重试一次。
func runOnSession[T any](p *provider, fn func(*Session) (T, error)) (T, error) {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()

	var zero T
	if p.isClosed() {
		return zero, fmt.Errorf("PKCS#11 后端已关闭")
	}
	s, err := p.ensureSession()
	if err != nil {
		return zero, err
	}
	out, err := fn(s)
	if err == nil {
		return out, nil
	}
	if !isSessionError(err) {
		return zero, err
	}
	p.invalidateSession()
	s2, err2 := p.ensureSession()
	if err2 != nil {
		return zero, err
	}
	return fn(s2)
}

func (p *provider) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// openSessionLocked 在设备操作锁内建立（或复用）会话。
func (p *provider) openSessionLocked() error {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()
	_, err := p.ensureSession()
	return err
}

func (p *provider) invalidateSession() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.session != nil {
		_ = p.session.Close()
		p.session = nil
	}
}

// isSessionError 判断错误是否属于「会话失效，可重建重试」。
func isSessionError(err error) bool {
	msg := err.Error()
	for _, s := range []string{"CKR_SESSION", "会话句柄无效", "会话已关闭", "设备已移除", "用户未登录"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	// 常见返回码的十六进制形态
	for _, s := range []string{"0x000000B0", "0x000000B3", "0x00000032", "0x00000101"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// findPrivateKey 按 CKA_ID 定位私钥对象。
func (s *Session) findPrivateKey(ref keyRef) (ckULong, error) {
	if ref.CKAID == "" {
		return 0, fmt.Errorf("私钥引用缺少 CKA_ID")
	}
	id, err := hex.DecodeString(ref.CKAID)
	if err != nil {
		return 0, fmt.Errorf("CKA_ID 非法: %w", err)
	}
	tmpl := newAttrBuffer(s.m.layout).addULong(ckaClass, ckoPrivateKey).add(ckaID, id)
	handles, err := s.FindObjects(tmpl, 4)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("设备中未找到私钥对象（CKA_ID=%s）；"+
			"请确认存储区域指向的令牌与生成密钥时一致，且设备未被重置", ref.CKAID)
	}
	return handles[0], nil
}

func decodeRef(ref string) (keyRef, error) {
	var out keyRef
	if strings.TrimSpace(ref) == "" {
		return out, fmt.Errorf("证书缺少 PKCS#11 私钥引用")
	}
	if _, err := keybackend.DecodeRef(ref, &out); err != nil {
		return out, err
	}
	return out, nil
}

func randomID() ([]byte, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("生成对象 ID 失败: %w", err)
	}
	return buf, nil
}

func shortLabel(hint string, id []byte) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		hint = "key"
	}
	if len(hint) > 24 {
		hint = hint[:24]
	}
	return fmt.Sprintf("%s-%s", hint, hex.EncodeToString(id[:4]))
}

// defaultPresets 返回常见厂商模块的预置参数。
func defaultPresets() []keybackend.Preset {
	return []keybackend.Preset{
		{
			ID:          "etoken5110",
			Name:        "SafeNet eToken 5110 / 5100（Thales）",
			Description: "安装 SafeNet Authentication Client 后自动注册 eTPKCS11.dll",
			Kind:        keybackend.KindHSM,
			Driver:      keybackend.DriverPKCS11,
			Params: map[string]string{
				"library": "${SYSTEM32}\\eTPKCS11.dll",
				"keygen":  "true",
			},
			SearchPaths: []string{
				`${SYSTEM32}\eTPKCS11.dll`,
				`C:\Windows\System32\eTPKCS11.dll`,
				`C:\Program Files\SafeNet\Authentication\SAC\x64\eTPKCS11.dll`,
				`C:\Program Files (x86)\SafeNet\Authentication\SAC\x64\eTPKCS11.dll`,
				"SAC/x64/eTPKCS11.dll",
			},
		},
		{
			ID:          "softhsm2",
			Name:        "SoftHSM v2（软件模拟，用于测试）",
			Description: "开发/测试环境常用的软件 PKCS#11 模块",
			Kind:        keybackend.KindHSM,
			Driver:      keybackend.DriverPKCS11,
			Params: map[string]string{
				"library": "/usr/lib/softhsm/libsofthsm2.so",
				"keygen":  "true",
			},
			SearchPaths: []string{
				"/usr/lib/softhsm/libsofthsm2.so",
				"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
				"/opt/homebrew/lib/softhsm/libsofthsm2.so",
				"/usr/local/lib/softhsm/libsofthsm2.so",
				`C:\SoftHSM2\lib\softhsm2-x64.dll`,
			},
		},
		{
			ID:          "yubikey-piv",
			Name:        "YubiKey PIV（ykcs11）",
			Description: "使用 YubiKey PIV 功能做私钥运算",
			Kind:        keybackend.KindHSM,
			Driver:      keybackend.DriverPKCS11,
			Params: map[string]string{
				"library": "ykcs11.dll",
				"keygen":  "true",
			},
			SearchPaths: []string{
				`C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll`,
				"/usr/local/lib/libykcs11.so",
				"/usr/lib/x86_64-linux-gnu/libykcs11.so",
			},
		},
		{
			ID:          "tpm2-pkcs11",
			Name:        "TPM2 PKCS#11（tpm2-pkcs11）",
			Description: "把本机 TPM 以 PKCS#11 形式暴露（Linux 常用，可作为 TPM 后端的替代方案）",
			Kind:        keybackend.KindHSM,
			Driver:      keybackend.DriverPKCS11,
			Params: map[string]string{
				"library": "/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so",
				"keygen":  "true",
			},
			SearchPaths: []string{
				"/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so",
				"/usr/local/lib/libtpm2_pkcs11.so",
			},
		},
	}
}
