# 测试与诊断脚本

以管理员 PowerShell 运行，需先 `Set-ExecutionPolicy Bypass -Scope Process`。

## 诊断类（排查问题用）

| 脚本 | 用途 |
|------|------|
| `diagnose_ksp.ps1` | **首选**。综合诊断：注册表、DLL 存在性、NCryptOpenStorageProvider 加载测试、路径权限 |
| `check_register.ps1` | 快速检查 KSP 注册表键是否存在、Image 值是否正确 |
| `check_provider.ps1` | 检查证书的 KeyProvInfo 属性，确认证书是否正确关联到 OpenCert KSP |
| `dump_reg.ps1` | 导出 KSP 相关注册表完整树状结构（用于问题报告） |

## 测试类（验证功能用）

| 脚本 | 用途 |
|------|------|
| `test_ksp.ps1` | 通过 NCrypt API 测试 KSP 完整流程：OpenProvider → OpenKey → SignHash |
| `test_sign.ps1` | 查找 OpenCert 证书并执行端到端签名测试（不依赖 signtool） |
| `test_manual_load.ps1` | 手动 LoadLibrary 加载 DLL，调用 GetKeyStorageInterface（排查 DLL 依赖/加载问题） |
| `compared_certs.ps1` | 对比 Windows 证书存储与 client-card 后端的证书一致性 |

## 推荐排查顺序

1. `diagnose_ksp.ps1` — 确认 KSP 安装正确
2. `test_manual_load.ps1` — 确认 DLL 能加载
3. `test_ksp.ps1` — 确认签名链路通
4. `test_sign.ps1` — 确认证书签名可用
