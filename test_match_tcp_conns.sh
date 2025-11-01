#!/usr/bin/env bash
# test_match_tcp_conns.sh - 测试TCP连接匹配工具
set -euo pipefail

echo "=========================================="
echo "TCP连接匹配工具测试套件"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数器
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 测试函数
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "测试 $TOTAL_TESTS: $test_name ... "
    
    if output=$(eval "$command" 2>&1); then
        if echo "$output" | grep -q "$expected_pattern"; then
            echo -e "${GREEN}通过${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        else
            echo -e "${RED}失败${NC}"
            echo "  预期包含: $expected_pattern"
            echo "  实际输出: $(echo "$output" | head -3)"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    else
        echo -e "${RED}失败${NC} (命令执行错误)"
        echo "  错误: $output"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# 检查依赖
echo "检查依赖..."
for cmd in tshark awk sort xxd md5sum; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "  ✓ $cmd"
    else
        echo -e "  ${RED}✗ $cmd (缺失)${NC}"
        exit 1
    fi
done
echo ""

# 检查测试文件
TEST_DIR="cases/TC-034-3-20210604-S"
A_FILE="$TEST_DIR/TC-034-3-20210604-S-A-Front-of-F5.pcapng"
B_FILE="$TEST_DIR/TC-034-3-20210604-S-B-Front-of-APP.pcapng"

if [[ ! -f "$A_FILE" ]]; then
    echo -e "${RED}错误: 测试文件不存在: $A_FILE${NC}"
    exit 1
fi

if [[ ! -f "$B_FILE" ]]; then
    echo -e "${RED}错误: 测试文件不存在: $B_FILE${NC}"
    exit 1
fi

echo "测试文件:"
echo "  A侧: $A_FILE"
echo "  B侧: $B_FILE"
echo ""

# 开始测试
echo "=========================================="
echo "开始测试"
echo "=========================================="
echo ""

# 测试1: 帮助信息(特殊处理,因为--help会exit 0)
TOTAL_TESTS=$((TOTAL_TESTS + 1))
echo -n "测试 $TOTAL_TESTS: 显示帮助信息 ... "
if output=$(./match_tcp_conns.sh --help 2>&1 || true); then
    if echo "$output" | grep -q "用法:"; then
        echo -e "${GREEN}通过${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}失败${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo -e "${RED}失败${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# 测试2: 自动检测分桶策略
run_test "自动检测分桶策略" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE'" \
    "✓ 决策: 使用 port 分桶"

# 测试3: 自动检测应该成功匹配
run_test "自动检测成功匹配" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE'" \
    "总计匹配: 1 对TCP连接"

# 测试4: 手动指定port分桶
run_test "手动指定port分桶" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket port" \
    "总计匹配: 1 对TCP连接"

# 测试5: 验证置信度
run_test "验证置信度范围" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket port" \
    "置信度: 0\.[0-9][0-9]"

# 测试6: 验证证据
run_test "验证匹配证据" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket port" \
    "证据:.*synopt"

# 测试7: 验证五元组输出
run_test "验证五元组输出" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket port" \
    "10.0.0.104:47525"

# 测试8: 测试不同的最低分数阈值
run_test "降低分数阈值" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket port --min-score 0.50" \
    "总计匹配:"

# 测试9: 测试header模式
run_test "Header-only模式" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket port --mode header" \
    "匹配模式: header"

# 测试10: 测试full模式
run_test "Full模式" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket port --mode full" \
    "匹配模式: full"

# 测试11: 测试server分桶(预期无匹配,因为服务器IP不同)
run_test "Server分桶(预期无匹配)" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket server" \
    "总计匹配: 0 对TCP连接"

# 测试12: 验证报文提取
run_test "验证报文提取" \
    "./match_tcp_conns.sh '$A_FILE' '$B_FILE' --bucket port" \
    "提取了.*个TCP报文"

echo ""
echo "=========================================="
echo "测试总结"
echo "=========================================="
echo "总测试数: $TOTAL_TESTS"
echo -e "通过: ${GREEN}$PASSED_TESTS${NC}"
echo -e "失败: ${RED}$FAILED_TESTS${NC}"
echo ""

if [[ $FAILED_TESTS -eq 0 ]]; then
    echo -e "${GREEN}所有测试通过!${NC}"
    exit 0
else
    echo -e "${RED}有 $FAILED_TESTS 个测试失败${NC}"
    exit 1
fi

