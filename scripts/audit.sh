#!/usr/bin/env bash
# 安全审计聚合脚本：串行执行 gosec / govulncheck / npm audit，
# 结果合并写入 roadmap/14-AUDIT-REPORT.md。
#
# 用法：
#   bash scripts/audit.sh           # 仅生成报告，发现高危 CVE 时退出码非 0
#   FAIL_ON_HIGH=0 bash audit.sh    # 不因高危 CVE 失败（仅生成报告）
#
# 依赖（缺失时自动跳过该子任务并在报告中标注）：
#   - gosec        (https://github.com/securego/gosec)
#   - govulncheck  (golang.org/x/vuln/cmd/govulncheck)
#   - npm          (Node.js)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPORT="$REPO_ROOT/roadmap/14-AUDIT-REPORT.md"
FAIL_ON_HIGH="${FAIL_ON_HIGH:-1}"
HAS_HIGH=0

mkdir -p "$(dirname "$REPORT")"

log()  { printf "\033[36m[audit]\033[0m %s\n" "$*"; }
warn() { printf "\033[33m[audit]\033[0m %s\n" "$*"; }

# ---- 写报告头 ----
{
    echo "# 14. 安全审计报告"
    echo
    echo "> 自动生成于 \`$(date -u +"%Y-%m-%dT%H:%M:%SZ")\`，由 \`scripts/audit.sh\` 输出。"
    echo "> 不要手工编辑本文件；下次执行 \`make audit\` 时将被覆盖。"
    echo
    echo "## 执行摘要"
    echo
    echo "| 子任务 | 命令 | 状态 |"
    echo "|--------|------|------|"
} > "$REPORT"

run_section() {
    local name="$1" cmd="$2" workdir="$3" tool_check="$4"
    local status outfile
    outfile="$(mktemp)"

    if ! command -v "$tool_check" >/dev/null 2>&1; then
        warn "  跳过 $name（未安装 $tool_check）"
        echo "| $name | \`$cmd\` | ⚠️ 跳过（未安装 $tool_check） |" >> "$REPORT"
        return 0
    fi

    log "运行 $name : $cmd"
    if (cd "$workdir" && eval "$cmd") >"$outfile" 2>&1; then
        status="✅ 通过"
    else
        status="❌ 失败"
        # gosec 与 govulncheck 失败均视为高危
        case "$name" in
            gosec*|govulncheck*) HAS_HIGH=1 ;;
        esac
    fi
    echo "| $name | \`$cmd\` | $status |" >> "$REPORT"

    {
        echo
        echo "## $name"
        echo
        echo "**命令**：\`$cmd\`（工作目录：\`$workdir\`）"
        echo
        echo "<details><summary>展开输出</summary>"
        echo
        echo '```'
        # 限制输出 500 行，避免报告过大
        head -n 500 "$outfile"
        echo '```'
        echo
        echo "</details>"
    } >> "$REPORT"

    rm -f "$outfile"
}

# ---- 1. Go 静态安全扫描（gosec） ----
run_section "gosec (clients)" "gosec -quiet -fmt=text ./..." "$REPO_ROOT/clients" "gosec"
run_section "gosec (servers)" "gosec -quiet -fmt=text ./..." "$REPO_ROOT/servers" "gosec"

# ---- 2. Go 漏洞数据库（govulncheck） ----
run_section "govulncheck (clients)" "govulncheck ./..." "$REPO_ROOT/clients" "govulncheck"
run_section "govulncheck (servers)" "govulncheck ./..." "$REPO_ROOT/servers" "govulncheck"

# ---- 3. 前端 npm audit ----
for fe in "clients/front" "servers/front"; do
    if [ -f "$REPO_ROOT/$fe/package.json" ]; then
        run_section "npm audit ($fe)" \
            "npm audit --omit=dev --audit-level=high --json || npm audit --omit=dev --audit-level=high" \
            "$REPO_ROOT/$fe" "npm"
    fi
done

# ---- 4. 基准测试结果（由 make bench 写入；这里读取已存在文件） ----
BENCH_FILE="$REPO_ROOT/roadmap/.bench-result.txt"
if [ -s "$BENCH_FILE" ]; then
    {
        echo
        echo "## 基准测试"
        echo
        echo '```'
        cat "$BENCH_FILE"
        echo '```'
    } >> "$REPORT"
fi

log "审计报告已生成：$REPORT"

# ---- 退出码控制 ----
if [ "$HAS_HIGH" -ne 0 ] && [ "$FAIL_ON_HIGH" = "1" ]; then
    warn "发现高危问题，退出码 1（设置 FAIL_ON_HIGH=0 跳过失败）"
    exit 1
fi
exit 0
