# 14. 安全审计报告

> 本文件由 `scripts/audit.sh` 自动生成，不要手工编辑。
> 执行 `make audit`（或 CI 上的 `audit` job）会覆盖本文件。

## 占位

首次执行 `make audit` 后，本文件将被替换为最新的审计结果，包含：

- gosec 静态扫描（clients / servers）
- govulncheck 漏洞扫描（clients / servers）
- npm audit（clients/front、servers/front）
- 基准测试结果（来自 `roadmap/.bench-result.txt`）

如需立即生成报告，请在仓库根目录执行：

```bash
make audit-full   # 先跑 bench 再跑 audit
```
