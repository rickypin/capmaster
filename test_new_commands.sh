#!/bin/bash

# 测试新增的两个 tshark 命令
# 1. TLS Alert 消息统计
# 2. HTTP 响应状态码统计

set -euo pipefail

# 颜色定义
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    GREEN='' BLUE='' YELLOW='' NC=''
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}测试新增的 tshark 命令${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 测试用例 1: TLS Alert 消息
echo -e "${YELLOW}测试 1: TLS Alert 消息统计${NC}"
echo -e "${BLUE}测试文件: cases/TC-006-02-20180518-1/TC-006-02-20180518-O-61.148.244.65.pcap${NC}"
./analyze_pcap.sh -i cases/TC-006-02-20180518-1/TC-006-02-20180518-O-61.148.244.65.pcap

echo ""
echo -e "${GREEN}查看 TLS Alert 消息统计结果:${NC}"
cat cases/TC-006-02-20180518-1/statistics/TC-006-02-20180518-O-61.148.244.65-10-tls-alert-message.txt | head -20
echo ""

# 测试用例 2: HTTP 响应状态码
echo -e "${YELLOW}测试 2: HTTP 响应状态码统计${NC}"
echo -e "${BLUE}测试文件: cases/TC-034-9-20230222-O-1/TC-034-9-20230222-O-A-nginx.pcap${NC}"
./analyze_pcap.sh -i cases/TC-034-9-20230222-O-1/TC-034-9-20230222-O-A-nginx.pcap

echo ""
echo -e "${GREEN}查看 HTTP 响应状态码统计结果:${NC}"
cat cases/TC-034-9-20230222-O-1/statistics/TC-034-9-20230222-O-A-nginx-11-http-response-code.txt
echo ""

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}测试完成！${NC}"
echo -e "${BLUE}========================================${NC}"

