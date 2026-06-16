// Package i18n 提供多语言国际化支持。
package i18n

import (
	"encoding/json"
	"fmt"
	"sync"
)

// translations 语言资源映射
var translations = map[string]map[string]string{}
var currentLang string
var mu sync.RWMutex

// Init 初始化多语言支持
func Init(lang string) {
	mu.Lock()
	defer mu.Unlock()
	currentLang = lang
	loadBuiltinTranslations()
}

// SetLanguage 切换语言
func SetLanguage(lang string) {
	mu.Lock()
	defer mu.Unlock()
	currentLang = lang
}

// T 翻译指定键值
func T(key string) string {
	mu.RLock()
	defer mu.RUnlock()
	if m, ok := translations[currentLang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	// 回退到中文
	if m, ok := translations["zh-CN"]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

// TF 翻译并格式化
func TF(key string, args ...interface{}) string {
	return fmt.Sprintf(T(key), args...)
}

// loadBuiltinTranslations 加载内置翻译
func loadBuiltinTranslations() {
	// ---- 中文 ----
	zhCN := map[string]string{
		// 应用
		"app.name":           "OpenCert 智能卡管理",
		"app.version":        "版本 %s",
		"app.copyright":      "© 2024-2026 GlobalTrusts",
		"app.about":          "关于",
		"app.close":          "关闭",
		"app.quit":           "退出",
		"app.ok":             "确定",
		"app.cancel":         "取消",
		"app.save":           "保存",
		"app.refresh":        "刷新",
		"app.delete":         "删除",
		"app.loading":        "加载中...",
		"app.error":          "错误",
		"app.success":        "操作成功",
		"app.confirm":        "确认",
		"app.confirm_delete": "确定要删除吗？此操作不可撤销。",
		"app.no_data":        "暂无数据",
		"app.connecting":     "连接中...",

		// 托盘
		"tray.manage_certs":    "管理证书",
		"tray.cert_list":       "证书列表",
		"tray.import_cert":     "导入证书",
		"tray.manage_cards":    "管理卡片",
		"tray.connect":         "连接",
		"tray.disconnect":      "断开连接",
		"tray.options":         "选项",
		"tray.about":           "关于",
		"tray.quit":            "退出",
		"tray.connected":       "已连接",
		"tray.disconnected":    "未连接",
		"tray.backend_offline": "后端离线",
		"tray.backend_online":  "后端在线",

		// 登录
		"login.title":             "登录认证",
		"login.local":             "本地登录",
		"login.cloud":             "云端登录",
		"login.username":          "账户",
		"login.password":          "密码",
		"login.cloud_url":         "云端地址",
		"login.submit":            "登录",
		"login.logout":            "注销",
		"login.success":           "登录成功",
		"login.failed":            "登录失败",
		"login.2fa_required":      "需要二次验证",
		"login.2fa_code":          "验证码",
		"login.2fa_hint":          "请输入身份验证器中的6位验证码",
		"login.username_hint":     "请输入用户名",
		"login.password_hint":     "请输入密码",
		"login.cloud_url_hint":    "例如: https://cloud.example.com",
		"login.remember_username": "记住账号",
		"login.remember_password": "记住密码",

		// 卡片
		"card.title":          "智能卡管理",
		"card.uuid":           "UUID",
		"card.name":           "名称",
		"card.slot_type":      "类型",
		"card.security_level": "安全等级",
		"card.created_at":     "创建时间",
		"card.expires_at":     "过期时间",
		"card.cert_count":     "证书数",
		"card.remark":         "备注",
		"card.enabled":        "已启用",
		"card.disabled":       "已禁用",
		"card.pin_locked":     "PIN已锁定",
		"card.view_detail":    "查看详情",
		"card.modify":         "修改",
		"card.generate_key":   "生成密钥对",
		"card.reset_pin":      "重置PIN",
		"card.backup":         "备份",
		"card.restore":        "恢复",
		"card.delete":         "删除卡片",
		"card.local":          "本地",
		"card.tpm2":           "TPM2",
		"card.tpmsc":          "TPM智能卡",
		"card.cloud":          "云端",
		"card.level_high":     "高",
		"card.level_medium":   "中",
		"card.level_low":      "低",
		"card.expired":        "已过期",

		// 证书
		"cert.title":                 "证书管理",
		"cert.list":                  "证书列表",
		"cert.uuid":                  "UUID",
		"cert.common_name":           "主题(CN)",
		"cert.type":                  "类型",
		"cert.serial":                "序列号",
		"cert.issuer":                "颁发者",
		"cert.valid_from":            "生效时间",
		"cert.valid_to":              "过期时间",
		"cert.key_type":              "密钥算法",
		"cert.card":                  "所属卡片",
		"cert.all_cards":             "全部",
		"cert.remark":                "备注",
		"cert.view_detail":           "查看详情",
		"cert.export":                "导出证书",
		"cert.export_key":            "导出密钥",
		"cert.delete":                "删除证书",
		"cert.deliver":               "下发",
		"cert.expired":               "已过期",
		"cert.x509":                  "X.509",
		"cert.hide_invalid":          "隐藏无效证书",
		"cert.detail.title":          "证书详情",
		"cert.detail.subject":        "主体信息",
		"cert.detail.issuer":         "颁发者信息",
		"cert.detail.subject_issuer": "主体与颁发者",
		"cert.detail.tech_info":      "技术信息",
		"cert.detail.extensions":     "扩展信息",
		"cert.detail.validity":       "有效期",
		"cert.detail.serial":         "序列号",
		"cert.detail.fingerprint":    "指纹",
		"cert.detail.key_usage":      "密钥用途",
		"cert.detail.ext_usage":      "扩展用途",
		"cert.detail.san":            "主题备用名称",
		"cert.detail.crl":            "CRL分发点",
		"cert.detail.ocsp":           "OCSP服务器",
		"cert.detail.aia":            "AIA(颁发者信息)",
		"cert.detail.policies":       "证书策略",
		"cert.detail.key_info":       "密钥信息",
		"cert.detail.other":          "其他信息",

		// 导入证书
		"import.title":         "导入证书",
		"import.target_card":   "目标卡片",
		"import.format":        "导入格式",
		"import.pem":           "PEM",
		"import.pfx":           "PFX/PKCS12",
		"import.cert_file":     "证书文件",
		"import.key_file":      "私钥文件",
		"import.pfx_file":      "PFX文件",
		"import.pfx_password":  "PFX密码",
		"import.card_password": "卡片密码",
		"import.remark":        "备注",
		"import.select_file":   "选择文件",
		"import.importing":     "正在导入...",
		"import.success":       "证书导入成功",
		"import.failed":        "证书导入失败",

		// 云端下发
		"deliver.title":            "云端证书下发",
		"deliver.target":           "下发目标",
		"deliver.target_db":        "本地数据库",
		"deliver.target_card":      "本地智能卡",
		"deliver.target_card_uuid": "目标卡片",
		"deliver.card_password":    "卡片密码",
		"deliver.remark":           "备注",
		"deliver.delivering":       "正在下发...",
		"deliver.success":          "证书下发成功",
		"deliver.failed":           "证书下发失败",

		// 选项
		"options.title":        "选项",
		"options.backend_url":  "后端服务地址",
		"options.language":     "界面语言",
		"options.hide_expired": "隐藏过期证书",
		"options.zh_cn":        "简体中文",
		"options.en_us":        "English",
		"options.save_success": "配置已保存",
		"options.restart_hint": "后端地址已更改，请重新连接。",

		// 密钥生成
		"keygen.title":    "生成密钥对",
		"keygen.type":     "密钥类型",
		"keygen.password": "密码",
		"keygen.remark":   "备注",
		"keygen.success":  "密钥对生成成功",
		"keygen.failed":   "密钥对生成失败",

		// 备份恢复
		"backup.password":  "备份密码",
		"backup.success":   "备份成功",
		"backup.failed":    "备份失败",
		"restore.data":     "备份数据",
		"restore.password": "恢复密码",
		"restore.success":  "恢复成功",
		"restore.failed":   "恢复失败",

		// TOTP 管理
		"totp.title":    "TOTP 管理",
		"totp.card":     "所属卡片",
		"totp.add":      "添加 TOTP",
		"totp.code":     "验证码",
		"totp.generate": "生成验证码",
		"totp.copied":   "验证码已复制到剪贴板",

		// FIDO 管理
		"fido.title": "FIDO 管理",
		"fido.card":  "所属卡片",
		"fido.add":   "注册 FIDO 凭据",
		"fido.type":  "FIDO 类型",
		"fido.u2f":   "U2F",
		"fido.fido2": "FIDO2",
		"fido.rp_id": "依赖方(RP) ID",
		"fido.user":  "用户名",

		// 安全凭据管理
		"creds.title":              "安全凭据",
		"creds.card":               "所属卡片",
		"creds.add":                "添加凭据",
		"creds.type":               "凭据类型",
		"creds.value":              "凭据值",
		"creds.username":           "用户名",
		"creds.password":           "密码",
		"creds.view":               "查看内容",
		"creds.content":            "凭据内容",
		"creds.decrypt":            "解密查看",
		"creds.card_password_hint": "请输入卡片密码",

		// TOTP
		"totp.get_code":           "获取验证码",
		"totp.card_password":      "卡片密码",
		"totp.card_password_hint": "请输入卡片密码",
	}
	translations["zh-CN"] = zhCN

	// ---- 英文 ----
	enUS := map[string]string{
		// App
		"app.name":           "GlobalTrusts Client",
		"app.version":        "Version %s",
		"app.copyright":      "© 2024-2026 GlobalTrusts",
		"app.about":          "About",
		"app.close":          "Close",
		"app.quit":           "Quit",
		"app.ok":             "OK",
		"app.cancel":         "Cancel",
		"app.save":           "Save",
		"app.refresh":        "Refresh",
		"app.delete":         "Delete",
		"app.loading":        "Loading...",
		"app.error":          "Error",
		"app.success":        "Success",
		"app.confirm":        "Confirm",
		"app.confirm_delete": "Are you sure you want to delete? This action cannot be undone.",
		"app.no_data":        "No data",
		"app.connecting":     "Connecting...",

		// Tray
		"tray.manage_certs":    "Manage Certificates",
		"tray.cert_list":       "Certificate List",
		"tray.import_cert":     "Import Certificate",
		"tray.manage_cards":    "Manage Cards",
		"tray.connect":         "Connect",
		"tray.disconnect":      "Disconnect",
		"tray.options":         "Options",
		"tray.about":           "About",
		"tray.quit":            "Quit",
		"tray.connected":       "Connected",
		"tray.disconnected":    "Disconnected",
		"tray.backend_offline": "Backend Offline",
		"tray.backend_online":  "Backend Online",

		// Login
		"login.title":             "Authentication",
		"login.local":             "Local Login",
		"login.cloud":             "Cloud Login",
		"login.username":          "Username",
		"login.password":          "Password",
		"login.cloud_url":         "Cloud URL",
		"login.submit":            "Login",
		"login.logout":            "Logout",
		"login.success":           "Login successful",
		"login.failed":            "Login failed",
		"login.2fa_required":      "2FA Required",
		"login.2fa_code":          "Verification Code",
		"login.2fa_hint":          "Enter the 6-digit code from your authenticator",
		"login.username_hint":     "Enter username",
		"login.password_hint":     "Enter password",
		"login.cloud_url_hint":    "e.g. https://cloud.example.com",
		"login.remember_username": "Remember Username",
		"login.remember_password": "Remember Password",

		// Card
		"card.title":          "Smart Card Management",
		"card.uuid":           "UUID",
		"card.name":           "Name",
		"card.slot_type":      "Type",
		"card.security_level": "Security Level",
		"card.created_at":     "Created",
		"card.expires_at":     "Expires",
		"card.cert_count":     "Certificates",
		"card.remark":         "Remark",
		"card.enabled":        "Enabled",
		"card.disabled":       "Disabled",
		"card.pin_locked":     "PIN Locked",
		"card.view_detail":    "View Details",
		"card.modify":         "Modify",
		"card.generate_key":   "Generate Key Pair",
		"card.reset_pin":      "Reset PIN",
		"card.backup":         "Backup",
		"card.restore":        "Restore",
		"card.delete":         "Delete Card",
		"card.local":          "Local",
		"card.tpm2":           "TPM2",
		"card.tpmsc":          "TPM SmartCard",
		"card.cloud":          "Cloud",
		"card.level_high":     "High",
		"card.level_medium":   "Medium",
		"card.level_low":      "Low",
		"card.expired":        "Expired",

		// Certificate
		"cert.title":                 "Certificate Management",
		"cert.list":                  "Certificate List",
		"cert.uuid":                  "UUID",
		"cert.common_name":           "Subject (CN)",
		"cert.type":                  "Type",
		"cert.serial":                "Serial Number",
		"cert.issuer":                "Issuer",
		"cert.valid_from":            "Valid From",
		"cert.valid_to":              "Valid To",
		"cert.key_type":              "Key Algorithm",
		"cert.card":                  "Card",
		"cert.all_cards":             "All",
		"cert.remark":                "Remark",
		"cert.view_detail":           "View Details",
		"cert.export":                "Export Certificate",
		"cert.export_key":            "Export Key",
		"cert.delete":                "Delete Certificate",
		"cert.deliver":               "Deliver",
		"cert.expired":               "Expired",
		"cert.x509":                  "X.509",
		"cert.hide_invalid":          "Hide invalid certificates",
		"cert.detail.title":          "Certificate Details",
		"cert.detail.subject":        "Subject Information",
		"cert.detail.issuer":         "Issuer Information",
		"cert.detail.subject_issuer": "Subject & Issuer",
		"cert.detail.tech_info":      "Technical Info",
		"cert.detail.extensions":     "Extensions",
		"cert.detail.validity":       "Validity",
		"cert.detail.serial":         "Serial Number",
		"cert.detail.fingerprint":    "Fingerprint",
		"cert.detail.key_usage":      "Key Usage",
		"cert.detail.ext_usage":      "Extended Key Usage",
		"cert.detail.san":            "Subject Alternative Names",
		"cert.detail.crl":            "CRL Distribution Points",
		"cert.detail.ocsp":           "OCSP Servers",
		"cert.detail.aia":            "AIA (Issuer Info)",
		"cert.detail.policies":       "Certificate Policies",
		"cert.detail.key_info":       "Key Information",
		"cert.detail.other":          "Other Information",

		// Import
		"import.title":         "Import Certificate",
		"import.target_card":   "Target Card",
		"import.format":        "Import Format",
		"import.pem":           "PEM",
		"import.pfx":           "PFX/PKCS12",
		"import.cert_file":     "Certificate File",
		"import.key_file":      "Private Key File",
		"import.pfx_file":      "PFX File",
		"import.pfx_password":  "PFX Password",
		"import.card_password": "Card Password",
		"import.remark":        "Remark",
		"import.select_file":   "Select File",
		"import.importing":     "Importing...",
		"import.success":       "Certificate imported successfully",
		"import.failed":        "Certificate import failed",

		// Deliver
		"deliver.title":            "Cloud Certificate Delivery",
		"deliver.target":           "Delivery Target",
		"deliver.target_db":        "Local Database",
		"deliver.target_card":      "Local Smart Card",
		"deliver.target_card_uuid": "Target Card",
		"deliver.card_password":    "Card Password",
		"deliver.remark":           "Remark",
		"deliver.delivering":       "Delivering...",
		"deliver.success":          "Certificate delivered successfully",
		"deliver.failed":           "Certificate delivery failed",

		// Options
		"options.title":        "Options",
		"options.backend_url":  "Backend URL",
		"options.language":     "Language",
		"options.hide_expired": "Hide expired certificates",
		"options.zh_cn":        "简体中文",
		"options.en_us":        "English",
		"options.save_success": "Configuration saved",
		"options.restart_hint": "Backend URL changed, please reconnect.",

		// Key Generation
		"keygen.title":    "Generate Key Pair",
		"keygen.type":     "Key Type",
		"keygen.password": "Password",
		"keygen.remark":   "Remark",
		"keygen.success":  "Key pair generated successfully",
		"keygen.failed":   "Key pair generation failed",

		// Backup/Restore
		"backup.password":  "Backup Password",
		"backup.success":   "Backup successful",
		"backup.failed":    "Backup failed",
		"restore.data":     "Backup Data",
		"restore.password": "Restore Password",
		"restore.success":  "Restore successful",
		"restore.failed":   "Restore failed",

		// TOTP Management
		"totp.title":    "TOTP Management",
		"totp.card":     "Card",
		"totp.add":      "Add TOTP",
		"totp.code":     "Code",
		"totp.generate": "Generate Code",
		"totp.copied":   "Code copied to clipboard",

		// FIDO Management
		"fido.title": "FIDO Management",
		"fido.card":  "Card",
		"fido.add":   "Register FIDO Credential",
		"fido.type":  "FIDO Type",
		"fido.u2f":   "U2F",
		"fido.fido2": "FIDO2",
		"fido.rp_id": "Relying Party ID",
		"fido.user":  "Username",

		// Credentials Management
		"creds.title":              "Credential Management",
		"creds.card":               "Card",
		"creds.add":                "Add Credential",
		"creds.type":               "Credential Type",
		"creds.value":              "Credential Value",
		"creds.username":           "Username",
		"creds.password":           "Password",
		"creds.view":               "View Content",
		"creds.content":            "Credential Content",
		"creds.decrypt":            "Decrypt & View",
		"creds.card_password_hint": "Enter card password",

		// TOTP
		"totp.get_code":           "Get Code",
		"totp.card_password":      "Card Password",
		"totp.card_password_hint": "Enter card password",
	}
	translations["en-US"] = enUS
}

// LoadFromJSON 从 JSON 字节加载翻译（预留扩展接口）
func LoadFromJSON(lang string, data []byte) error {
	m := make(map[string]string)
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("加载翻译失败: %w", err)
	}
	mu.Lock()
	translations[lang] = m
	mu.Unlock()
	return nil
}
