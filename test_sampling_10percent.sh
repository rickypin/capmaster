#!/usr/bin/env bash
# 测试10%采样率

set -euo pipefail

echo "=========================================="
echo "10%采样率验证测试"
echo "=========================================="
echo ""

echo "测试1: 强制采样到10% (68个连接)"
echo "----------------------------------------"
bash match_tcp_conns.sh \
  ./cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-in.pcap \
  ./cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-out.pcap \
  --sample 7 2>&1 | grep -E "采样统计" -A 3
echo ""

echo "测试2: 验证异常连接保护机制"
echo "----------------------------------------"
bash match_tcp_conns.sh \
  ./cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-in.pcap \
  ./cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-out.pcap \
  --sample 7 2>&1 | grep -E "异常连接识别"
echo ""

echo "测试3: 验证时间分层覆盖"
echo "----------------------------------------"
bash match_tcp_conns.sh \
  ./cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-in.pcap \
  ./cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-out.pcap \
  --sample 7 2>&1 | grep -E "时间范围"
echo ""

echo "测试4: 理论采样率计算"
echo "----------------------------------------"
echo "连接数 | 目标采样数 | 采样率"
echo "-------|-----------|-------"
for count in 1500 5000 10000 20000 30000 50000; do
  target=$(awk -v count="$count" 'BEGIN {
    target = int(count * 0.10 + 0.5)
    if (target < 100) target = 100
    if (count > 30000 && target > 3000) target = 3000
    print target
  }')
  rate=$(awk -v t=$target -v c=$count 'BEGIN {printf "%.1f%%", t*100.0/c}')
  printf "%6d | %10d | %s\n" $count $target "$rate"
done
echo ""

echo "=========================================="
echo "测试完成"
echo "=========================================="
