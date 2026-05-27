#!/usr/bin/env bash
# 基准测试聚合脚本：执行 client/server 的 go test -bench，结果合并写入
# roadmap/.bench-result.txt（供 audit.sh 拼接到审计报告）。
#
# 用法：
#   bash scripts/bench.sh
#
# 环境变量：
#   BENCH_TIME     单项基准最少运行时间（默认 1s）
#   BENCH_PATTERN  基准函数过滤（默认 .，匹配全部）

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_ROOT/roadmap/.bench-result.txt"
BENCH_TIME="${BENCH_TIME:-1s}"
BENCH_PATTERN="${BENCH_PATTERN:-.}"

mkdir -p "$(dirname "$OUT")"
: > "$OUT"

log() { printf "\033[36m[bench]\033[0m %s\n" "$*"; }

run_bench() {
    local name="$1" workdir="$2" target="$3"
    log "运行 $name ：cd $workdir && go test -bench=$BENCH_PATTERN -benchmem -benchtime=$BENCH_TIME -run=^$ $target"
    {
        echo "===== $name ====="
        echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "Cmd : go test -bench=$BENCH_PATTERN -benchmem -benchtime=$BENCH_TIME -run=^$ $target"
        echo
    } >> "$OUT"

    if (cd "$workdir" && go test -bench="$BENCH_PATTERN" -benchmem \
            -benchtime="$BENCH_TIME" -run='^$' $target 2>&1); then
        :
    else
        echo "(基准测试失败，详见上方日志)" >> "$OUT"
    fi >> "$OUT"
    echo >> "$OUT"
}

run_bench "clients/test"            "$REPO_ROOT/clients" "./test/..."
run_bench "servers/test"            "$REPO_ROOT/servers" "./test/..."

log "基准结果写入：$OUT"
