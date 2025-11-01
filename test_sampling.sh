#!/usr/bin/env bash
# 测试采样功能的各种场景

set -euo pipefail

SCRIPT="./match_tcp_conns.sh"
PCAP_A="./cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-in.pcap"
PCAP_B="./cases/TC-002-5-20220215-O/TC-002-5-20220215-O-FW-out.pcap"

echo "=========================================="
echo "采样功能测试"
echo "=========================================="
echo ""

# 测试1: 默认模式(auto)
echo "测试1: 默认模式 (--sample auto)"
echo "----------------------------------------"
bash "$SCRIPT" "$PCAP_A" "$PCAP_B" 2>&1 | grep -E "采样|连接数" | head -5
echo ""

# 测试2: 强制不采样
echo "测试2: 强制不采样 (--sample off)"
echo "----------------------------------------"
bash "$SCRIPT" "$PCAP_A" "$PCAP_B" --sample off 2>&1 | grep -E "采样|连接数" | head -5
echo ""

# 测试3: 强制采样到30个
echo "测试3: 强制采样 (--sample 30)"
echo "----------------------------------------"
bash "$SCRIPT" "$PCAP_A" "$PCAP_B" --sample 30 2>&1 | grep -E "采样|连接数|时间范围|异常" | head -15
echo ""

# 测试4: 强制采样到10个
echo "测试4: 强制采样 (--sample 10)"
echo "----------------------------------------"
bash "$SCRIPT" "$PCAP_A" "$PCAP_B" --sample 10 2>&1 | grep -E "采样统计" -A 5
echo ""

echo "=========================================="
echo "所有测试完成"
echo "=========================================="

