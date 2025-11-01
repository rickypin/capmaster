#!/bin/bash

# 脚本功能：去除捕获丢失导致的单向 TCP 连接噪音
# 用法: ./remove_one_way_tcp -i <input> [-o <output_path>] [-t <threshold>]
# 示例: ./remove_one_way_tcp -i test.pcap
#      ./remove_one_way_tcp -i file1.pcap,file2.pcapng -o output/
#      ./remove_one_way_tcp -i cases/test/ -t 100

# 严格模式
set -euo pipefail

# 颜色定义（仅在交互式终端使用）
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# ============================================
# 默认配置
# ============================================
DEFAULT_ACK_THRESHOLD=20

# ============================================
# 函数定义
# ============================================

# 显示使用说明
show_usage() {
    cat << EOF
用法: $0 -i <input> [-o <output_path>] [-t <threshold>]

参数:
  -i <input>    输入文件或目录
                - 单个文件: -i test.pcap
                - 多个文件（逗号分隔）: -i file1.pcap,file2.pcapng
                - 目录: -i cases/test/ (自动扫描目录及子目录下的 pcap/pcapng 文件)
                - 可多次使用 -i 参数
  -o <path>     输出目录路径（可选）
                - 如不指定，默认输出到原文件所在目录
  -t <num>      ACK 增量阈值（可选，默认: 20)
                - 用于判断是否为单向捕获，建议 >= 20
  -h            显示此帮助信息

示例:
  $0 -i test.pcap
  $0 -i test.pcap -o output/
  $0 -i file1.pcap,file2.pcapng
  $0 -i cases/test/
  $0 -i cases/test/ -t 100 -o results/

EOF
}

# 检查文件是否为 pcap/pcapng 格式
validate_pcap_file() {
    local file="$1"
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}错误: 文件不存在: $file${NC}" >&2
        return 1
    fi
    
    local ext="${file##*.}"
    ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$ext" != "pcap" && "$ext" != "pcapng" ]]; then
        echo -e "${RED}错误: 文件不是 pcap/pcapng 格式: $file${NC}" >&2
        return 1
    fi
    
    return 0
}

# 扫描目录中的 pcap/pcapng 文件（包括子目录）
scan_directory_for_pcap() {
    local dir="$1"
    local -a found_files=()

    if [ ! -d "$dir" ]; then
        echo -e "${RED}错误: 不是有效的目录: $dir${NC}" >&2
        return 1
    fi

    # 查找 .pcap 和 .pcapng 文件（包括子目录）
    while IFS= read -r -d '' file; do
        found_files+=("$file")
    done < <(find "$dir" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) -print0 2>/dev/null)

    if [ ${#found_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}警告: 目录中未找到 pcap/pcapng 文件: $dir${NC}" >&2
        return 1
    fi

    printf '%s\n' "${found_files[@]}"
    return 0
}

# 解析输入参数（支持逗号分隔的文件列表）
parse_input_argument() {
    local input="$1"
    local -a result_files=()

    if [ -d "$input" ]; then
        local -a dir_files=()
        while IFS= read -r file; do
            dir_files+=("$file")
        done < <(scan_directory_for_pcap "$input")

        if [ ${#dir_files[@]} -gt 0 ]; then
            result_files+=("${dir_files[@]}")
        fi
    else
        IFS=',' read -ra files <<< "$input"
        for file in "${files[@]}"; do
            file=$(echo "$file" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            if [ -n "$file" ]; then
                result_files+=("$file")
            fi
        done
    fi

    printf '%s\n' "${result_files[@]}"
    return 0
}

# 识别单向 TCP 连接（捕获丢失导致）
identify_one_way_tcp_streams() {
    local input_file="$1"
    local threshold="$2"
    local -a one_way_streams=()

    echo -e "${BLUE}分析 TCP 连接...${NC}"

    # 创建临时文件
    local temp_dir=$(mktemp -d)
    local all_data="$temp_dir/all_data.txt"
    local stream_stats="$temp_dir/stream_stats.txt"

    # 一次性提取所有需要的数据
    tshark -r "$input_file" -Y "tcp" \
        -T fields -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.ack -e tcp.len \
        2>/dev/null > "$all_data"

    if [ ! -s "$all_data" ]; then
        echo -e "${YELLOW}未找到 TCP 报文${NC}"
        rm -rf "$temp_dir"
        return 1
    fi

    # 使用 awk 进行批量分析
    awk -F'\t' -v threshold="$threshold" '
    {
        stream = $1
        src_ip = $2
        src_port = $3
        dst_ip = $4
        dst_port = $5
        ack = $6
        tcp_len = $7

        # 构建方向键
        direction = src_ip ":" src_port "->" dst_ip ":" dst_port
        key = stream ":" direction

        # 统计方向报文数
        dir_count[key]++

        # 记录流的第一个方向（用于后续判断反向）
        if (!(stream in stream_first_dir)) {
            stream_first_dir[stream] = direction
            stream_first_src[stream] = src_ip ":" src_port
            stream_first_dst[stream] = dst_ip ":" dst_port
        }

        # 记录 ACK 信息
        if (ack != "" && ack != "0") {
            if (!(key in first_ack)) {
                first_ack[key] = ack
            }
            last_ack[key] = ack

            # 检查纯 ACK
            if (tcp_len == "0") {
                if (key in prev_ack && ack > prev_ack[key]) {
                    has_pure_ack[key] = 1
                }
            }
            prev_ack[key] = ack
        }
    }
    END {
        # 分析每个流
        for (stream in stream_first_dir) {
            # 构建两个方向的键
            first_dir = stream_first_dir[stream]
            src = stream_first_src[stream]
            dst = stream_first_dst[stream]

            # 反向方向
            split(src, src_parts, ":")
            split(dst, dst_parts, ":")
            reverse_dir = dst_parts[1] ":" dst_parts[2] "->" src_parts[1] ":" src_parts[2]

            forward_key = stream ":" first_dir
            reverse_key = stream ":" reverse_dir

            forward_count = dir_count[forward_key] + 0
            reverse_count = dir_count[reverse_key] + 0

            # 检查是否为单向流
            if (forward_count == 0 || reverse_count == 0) {
                # 确定活跃方向
                active_key = (forward_count > 0) ? forward_key : reverse_key
                active_dir = (forward_count > 0) ? first_dir : reverse_dir

                # 检查 ACK 增量
                f_ack = first_ack[active_key] + 0
                l_ack = last_ack[active_key] + 0

                if (f_ack == 0 || l_ack == 0) continue

                # 计算 ACK 增量（处理回绕）
                if (l_ack >= f_ack) {
                    ack_delta = l_ack - f_ack
                } else {
                    ack_delta = 4294967296 + l_ack - f_ack
                }

                # 检查阈值和纯 ACK
                if (ack_delta > threshold && has_pure_ack[active_key] == 1) {
                    print stream "\t" active_dir "\t" ack_delta
                }
            }
        }
    }
    ' "$all_data" > "$stream_stats"

    # 读取结果
    if [ -s "$stream_stats" ]; then
        while IFS=$'\t' read -r stream_id direction ack_delta; do
            one_way_streams+=("$stream_id")
            echo -e "${YELLOW}发现单向 TCP 流: stream=$stream_id ($direction) ack_delta=$ack_delta${NC}"
        done < "$stream_stats"
    fi

    # 清理临时文件
    rm -rf "$temp_dir"

    # 输出结果
    if [ ${#one_way_streams[@]} -gt 0 ]; then
        printf '%s\n' "${one_way_streams[@]}"
        return 0
    else
        return 1
    fi
}

# 处理单个文件
process_single_file() {
    local input_file="$1"
    local output_dir="$2"
    local threshold="$3"

    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}处理文件: $input_file${NC}"
    echo -e "${BLUE}========================================${NC}"

    if ! validate_pcap_file "$input_file"; then
        echo -e "${RED}跳过文件: $input_file${NC}"
        return 1
    fi

    # 识别单向 TCP 流
    local -a one_way_streams=()
    local temp_output
    temp_output=$(identify_one_way_tcp_streams "$input_file" "$threshold" 2>&1)

    # 从输出中提取流 ID（纯数字行）
    while IFS= read -r line; do
        if [[ "$line" =~ ^[0-9]+$ ]]; then
            one_way_streams+=("$line")
        fi
    done <<< "$temp_output"

    # 显示分析输出（包括发现的流信息）
    echo "$temp_output" | grep -v "^[0-9]\+$" || true

    if [ ${#one_way_streams[@]} -eq 0 ]; then
        echo -e "${GREEN}未发现单向 TCP 连接，无需过滤${NC}"
        echo ""
        return 0
    fi

    echo -e "${YELLOW}总计发现 ${#one_way_streams[@]} 个单向 TCP 流${NC}"

    # 构建过滤表达式
    local filter=""
    for stream_id in "${one_way_streams[@]}"; do
        if [ -z "$filter" ]; then
            filter="tcp.stream != $stream_id"
        else
            filter="$filter and tcp.stream != $stream_id"
        fi
    done

    # 确定输出文件路径
    local base_name="${input_file%.*}"
    local ext="${input_file##*.}"
    local output_file

    if [ -n "$output_dir" ]; then
        local filename=$(basename "$base_name")
        output_file="${output_dir}/${filename}-OWTR.${ext}"
    else
        output_file="${base_name}-OWTR.${ext}"
    fi

    echo -e "${BLUE}过滤并保存到: $output_file${NC}"

    # 执行过滤
    if tshark -r "$input_file" -Y "$filter" -w "$output_file" 2>/dev/null; then
        echo -e "${GREEN}✓ 成功创建过滤后的文件${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}✗ 过滤失败${NC}" >&2
        echo ""
        return 1
    fi
}

# ============================================
# 主程序
# ============================================

declare -a INPUT_ARGS=()
OUTPUT_DIR=""
ACK_THRESHOLD=$DEFAULT_ACK_THRESHOLD
USE_DEFAULT_OUTPUT=true

# 解析命令行参数
while getopts "i:o:t:h" opt; do
    case $opt in
        i)
            INPUT_ARGS+=("$OPTARG")
            ;;
        o)
            OUTPUT_DIR="$OPTARG"
            USE_DEFAULT_OUTPUT=false
            ;;
        t)
            ACK_THRESHOLD="$OPTARG"
            ;;
        h)
            show_usage
            exit 0
            ;;
        \?)
            echo -e "${RED}无效选项: -$OPTARG${NC}" >&2
            show_usage
            exit 1
            ;;
        :)
            echo -e "${RED}选项 -$OPTARG 需要参数${NC}" >&2
            show_usage
            exit 1
            ;;
    esac
done

# 检查必需参数
if [ ${#INPUT_ARGS[@]} -eq 0 ]; then
    echo -e "${RED}错误: 至少需要指定一个输入 (-i)${NC}" >&2
    show_usage
    exit 1
fi

# 解析所有输入参数
declare -a INPUT_FILES=()
echo -e "${BLUE}解析输入参数...${NC}"

for input_arg in "${INPUT_ARGS[@]}"; do
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            INPUT_FILES+=("$file")
        fi
    done < <(parse_input_argument "$input_arg")
done

if [ ${#INPUT_FILES[@]} -eq 0 ]; then
    echo -e "${RED}错误: 未找到任何有效的 pcap/pcapng 文件${NC}" >&2
    exit 1
fi

echo -e "${GREEN}找到 ${#INPUT_FILES[@]} 个输入文件${NC}"
echo ""

# 检查 tshark
if ! command -v tshark >/dev/null 2>&1; then
    echo -e "${RED}错误: 未找到 tshark 命令${NC}" >&2
    exit 1
fi

# 创建输出目录
if [ "$USE_DEFAULT_OUTPUT" = false ]; then
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        echo -e "${RED}错误: 无法创建输出目录: $OUTPUT_DIR${NC}" >&2
        exit 1
    fi
    OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
fi

# 显示配置
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}单向 TCP 连接过滤脚本${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}ACK 增量阈值: $ACK_THRESHOLD${NC}"
echo -e "${GREEN}输入文件数量: ${#INPUT_FILES[@]}${NC}"
if [ "$USE_DEFAULT_OUTPUT" = false ]; then
    echo -e "${GREEN}输出目录: $OUTPUT_DIR${NC}"
else
    echo -e "${GREEN}输出模式: 默认（原文件所在目录）${NC}"
fi
echo -e "${BLUE}========================================${NC}"
echo ""

# 处理每个文件
total_files=0
processed_files=0
filtered_files=0
failed_files=0

for input_file in "${INPUT_FILES[@]}"; do
    total_files=$((total_files + 1))

    _local_output_dir=""
    if [ "$USE_DEFAULT_OUTPUT" = false ]; then
        _local_output_dir="$OUTPUT_DIR"
    fi

    if process_single_file "$input_file" "$_local_output_dir" "$ACK_THRESHOLD"; then
        processed_files=$((processed_files + 1))
        # 检查是否创建了输出文件
        _base_name="${input_file%.*}"
        _ext="${input_file##*.}"
        if [ -n "$_local_output_dir" ]; then
            _filename=$(basename "$_base_name")
            _output_file="${_local_output_dir}/${_filename}-OWTR.${_ext}"
        else
            _output_file="${_base_name}-OWTR.${_ext}"
        fi
        if [ -f "$_output_file" ]; then
            filtered_files=$((filtered_files + 1))
        fi
    else
        failed_files=$((failed_files + 1))
    fi
done

# 显示总结
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}执行总结${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "总文件数: $total_files"
echo -e "${GREEN}成功处理: $processed_files${NC}"
echo -e "${GREEN}已过滤: $filtered_files${NC}"
if [ "$failed_files" -gt 0 ]; then
    echo -e "${RED}处理失败: $failed_files${NC}"
else
    echo -e "处理失败: $failed_files"
fi
echo -e "${BLUE}========================================${NC}"

if [ "$failed_files" -gt 0 ]; then
    exit 1
else
    exit 0
fi

