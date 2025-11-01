#!/bin/bash

# 脚本功能：对 pcap/pcapng 文件执行可配置的 tshark 分析命令
# 用法: ./analyze_pcap.sh -i <input_file1> [-i <input_file2> ...] [-c <config_file>] [-o <output_path>]
# 示例: ./analyze_pcap.sh -i test.pcap -o output/
#      ./analyze_pcap.sh -i file1.pcap -i file2.pcapng -c custom_commands.conf -o results/

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
# 默认配置文件路径
# ============================================
DEFAULT_CONFIG_FILE="tshark_commands.conf"

# ============================================
# tshark 命令列表（从配置文件加载）
# ============================================
declare -a TSHARK_COMMANDS=()

# ============================================
# 检测到的协议列表（从 pcap 文件中检测）
# ============================================
declare -a DETECTED_PROTOCOLS=()

# ============================================
# 函数定义
# ============================================

# 显示使用说明
show_usage() {
    cat << EOF
用法: $0 -i <input> [-c <config_file>] [-o <output_path>]

参数:
  -i <input>    输入文件或目录
                - 单个文件: -i test.pcap
                - 多个文件（逗号分隔）: -i file1.pcap,file2.pcapng
                - 目录: -i cases/test/ (自动扫描目录下的 pcap/pcapng 文件)
                - 可多次使用 -i 参数
  -c <config>   tshark 命令配置文件路径（可选）
                - 如不指定，默认使用 $DEFAULT_CONFIG_FILE
                - 配置文件格式: 命令模板::输出文件名后缀
  -o <path>     输出目录路径（可选）
                - 如不指定，默认使用输入文件所在目录下的 statistics/ 子目录
  -h            显示此帮助信息

示例:
  $0 -i test.pcap
  $0 -i test.pcap -o output/
  $0 -i test.pcap -c custom_commands.conf
  $0 -i file1.pcap,file2.pcapng
  $0 -i cases/test/
  $0 -i cases/test/ -c my_config.conf -o analysis/

EOF
}

# 检测 pcap 文件中包含的协议
detect_protocols() {
    local input_file="$1"

    echo -e "${BLUE}检测 pcap 文件中的协议...${NC}"

    # 清空协议列表
    DETECTED_PROTOCOLS=()

    # 执行协议分布统计命令
    local phs_output
    if ! phs_output=$(tshark -r "$input_file" -q -z io,phs 2>&1); then
        echo -e "${RED}错误: 无法执行协议检测命令${NC}" >&2
        return 1
    fi

    # 解析协议名称（提取每行开头的协议名，忽略缩进）
    # 协议名称格式示例: "  tcp", "    ssh", "  udp"
    while IFS= read -r line; do
        # 跳过分隔线和标题行
        if [[ "$line" =~ ^=+ ]] || [[ "$line" =~ ^Protocol ]] || [[ "$line" =~ ^Filter: ]] || [ -z "$line" ]; then
            continue
        fi

        # 提取协议名（去除前导空格和统计信息）
        # 格式: "  tcp                                frames:184 bytes:27279"
        if [[ "$line" =~ ^[[:space:]]*([a-zA-Z0-9_-]+) ]]; then
            local protocol="${BASH_REMATCH[1]}"
            # 转换为小写
            protocol=$(echo "$protocol" | tr '[:upper:]' '[:lower:]')
            # 添加到协议列表（避免重复）
            if [ ${#DETECTED_PROTOCOLS[@]} -eq 0 ] || [[ ! " ${DETECTED_PROTOCOLS[@]} " =~ " ${protocol} " ]]; then
                DETECTED_PROTOCOLS+=("$protocol")
            fi
        fi
    done <<< "$phs_output"

    if [ ${#DETECTED_PROTOCOLS[@]} -eq 0 ]; then
        echo -e "${YELLOW}警告: 未检测到任何协议${NC}" >&2
        return 1
    fi

    echo -e "${GREEN}检测到 ${#DETECTED_PROTOCOLS[@]} 种协议: ${DETECTED_PROTOCOLS[*]}${NC}"
    return 0
}

# 检查协议是否在检测列表中
protocol_exists() {
    local required_protocols="$1"

    # 如果协议标识为空或 "all"，总是返回成功
    if [ -z "$required_protocols" ] || [ "$required_protocols" = "all" ]; then
        return 0
    fi

    # 如果没有检测到任何协议，返回失败
    if [ ${#DETECTED_PROTOCOLS[@]} -eq 0 ]; then
        return 1
    fi

    # 转换为小写
    required_protocols=$(echo "$required_protocols" | tr '[:upper:]' '[:lower:]')

    # 分割多个协议（逗号分隔）
    IFS=',' read -ra protocols <<< "$required_protocols"

    # 检查是否至少有一个协议存在
    for protocol in "${protocols[@]}"; do
        # 去除前后空格
        protocol=$(echo "$protocol" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

        # 检查协议是否在检测列表中
        if [[ " ${DETECTED_PROTOCOLS[@]} " =~ " ${protocol} " ]]; then
            return 0
        fi
    done

    # 没有找到任何匹配的协议
    return 1
}

# 加载配置文件中的 tshark 命令
load_config_file() {
    local config_file="$1"

    # 检查配置文件是否存在
    if [ ! -f "$config_file" ]; then
        echo -e "${RED}错误: 配置文件不存在: $config_file${NC}" >&2
        return 1
    fi

    # 检查配置文件是否可读
    if [ ! -r "$config_file" ]; then
        echo -e "${RED}错误: 配置文件不可读: $config_file${NC}" >&2
        return 1
    fi

    echo -e "${BLUE}加载配置文件: $config_file${NC}"

    # 清空现有命令列表
    TSHARK_COMMANDS=()

    local line_num=0
    local loaded_count=0

    # 逐行读取配置文件
    while IFS= read -r line || [ -n "$line" ]; do
        line_num=$((line_num + 1))

        # 去除前后空格
        line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

        # 跳过空行和注释行
        if [ -z "$line" ] || [[ "$line" =~ ^# ]]; then
            continue
        fi

        # 检查是否包含分隔符 ::
        if [[ ! "$line" =~ :: ]]; then
            echo -e "${YELLOW}警告: 第 $line_num 行格式不正确（缺少 :: 分隔符），已跳过${NC}" >&2
            continue
        fi

        # 验证格式：至少需要两个字段（命令::后缀），第三个字段（协议）可选
        local field_count=$(echo "$line" | grep -o "::" | wc -l)
        if [ "$field_count" -lt 1 ]; then
            echo -e "${YELLOW}警告: 第 $line_num 行格式不正确，已跳过${NC}" >&2
            continue
        fi

        # 添加到命令列表
        TSHARK_COMMANDS+=("$line")
        loaded_count=$((loaded_count + 1))
    done < "$config_file"

    if [ ${#TSHARK_COMMANDS[@]} -eq 0 ]; then
        echo -e "${RED}错误: 配置文件中没有有效的命令${NC}" >&2
        return 1
    fi

    echo -e "${GREEN}成功加载 $loaded_count 条命令${NC}"
    return 0
}

# 检查文件是否为 pcap/pcapng 格式
validate_pcap_file() {
    local file="$1"
    
    # 检查文件是否存在
    if [ ! -f "$file" ]; then
        echo -e "${RED}错误: 文件不存在: $file${NC}" >&2
        return 1
    fi
    
    # 检查文件扩展名
    local ext="${file##*.}"
    ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$ext" != "pcap" && "$ext" != "pcapng" ]]; then
        echo -e "${RED}错误: 文件不是 pcap/pcapng 格式: $file${NC}" >&2
        echo -e "${RED}      文件扩展名: .$ext${NC}" >&2
        return 1
    fi
    
    # 使用 file 命令验证文件类型（如果可用）
    if command -v file >/dev/null 2>&1; then
        local file_type
        file_type=$(file -b "$file")
        if [[ ! "$file_type" =~ (pcap|tcpdump|capture) ]]; then
            echo -e "${YELLOW}警告: 文件扩展名为 .$ext，但 file 命令识别为: $file_type${NC}" >&2
            echo -e "${YELLOW}      将继续尝试处理...${NC}" >&2
        fi
    fi
    
    return 0
}

# 从文件路径提取文件名（不含扩展名）
get_basename_without_ext() {
    local filepath="$1"
    local filename
    filename=$(basename "$filepath")
    # 移除 .pcap 或 .pcapng 扩展名
    echo "${filename%.*}"
}

# 扫描目录中的 pcap/pcapng 文件
scan_directory_for_pcap() {
    local dir="$1"
    local -a found_files=()

    if [ ! -d "$dir" ]; then
        echo -e "${RED}错误: 不是有效的目录: $dir${NC}" >&2
        return 1
    fi

    # 查找 .pcap 和 .pcapng 文件
    while IFS= read -r -d '' file; do
        found_files+=("$file")
    done < <(find "$dir" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) -print0 2>/dev/null)

    if [ ${#found_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}警告: 目录中未找到 pcap/pcapng 文件: $dir${NC}" >&2
        return 1
    fi

    # 输出找到的文件（每行一个）
    printf '%s\n' "${found_files[@]}"
    return 0
}

# 解析输入参数（支持逗号分隔的文件列表）
parse_input_argument() {
    local input="$1"
    local -a result_files=()

    # 检查是否为目录
    if [ -d "$input" ]; then
        # 扫描目录
        local -a dir_files=()
        while IFS= read -r file; do
            dir_files+=("$file")
        done < <(scan_directory_for_pcap "$input")

        if [ ${#dir_files[@]} -gt 0 ]; then
            result_files+=("${dir_files[@]}")
        fi
    else
        # 按逗号分割文件列表
        IFS=',' read -ra files <<< "$input"
        for file in "${files[@]}"; do
            # 去除前后空格
            file=$(echo "$file" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            if [ -n "$file" ]; then
                result_files+=("$file")
            fi
        done
    fi

    # 输出结果文件（每行一个）
    printf '%s\n' "${result_files[@]}"
    return 0
}

# 获取默认输出目录（输入文件所在目录下的 statistics 子目录）
get_default_output_dir() {
    local input_file="$1"
    local file_dir

    # 获取文件所在目录
    file_dir=$(dirname "$input_file")

    # 获取绝对路径
    if [ -d "$file_dir" ]; then
        file_dir=$(cd "$file_dir" && pwd)
    fi

    echo "${file_dir}/statistics"
}

# 执行单个 tshark 命令
execute_tshark_command() {
    local input_file="$1"
    local cmd_template="$2"
    local output_suffix="$3"
    local output_dir="$4"
    local base_name="$5"
    local sequence_num="$6"
    local required_protocol="$7"

    # 检查协议依赖
    if ! protocol_exists "$required_protocol"; then
        echo -e "${YELLOW}跳过: 所需协议 [$required_protocol] 不存在${NC}"
        return 2  # 返回特殊退出码表示跳过
    fi

    # 替换命令模板中的占位符
    local actual_cmd="${cmd_template//\{INPUT\}/$input_file}"

    # 构建输出文件路径（使用序号前缀）
    local output_file="${output_dir}/${base_name}-${sequence_num}-${output_suffix}"

    # 检查输出文件是否存在
    if [ -f "$output_file" ]; then
        echo -e "${YELLOW}注意: 输出文件已存在，将被覆盖: $(basename "$output_file")${NC}"
    fi

    echo -e "${YELLOW}执行命令: ${actual_cmd}${NC}"
    echo -e "${BLUE}输出到: ${output_file}${NC}"

    # 执行命令并捕获输出（直接覆盖已存在的文件）
    if eval "$actual_cmd" > "$output_file" 2>&1; then
        echo -e "${GREEN}✓ 成功${NC}"
        return 0
    else
        local exit_code=$?
        echo -e "${RED}✗ 失败 (退出码: $exit_code)${NC}" >&2
        return $exit_code
    fi
}

# 处理单个输入文件
process_single_file() {
    local input_file="$1"
    local output_dir="$2"
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}处理文件: $input_file${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # 验证文件格式
    if ! validate_pcap_file "$input_file"; then
        echo -e "${RED}跳过文件: $input_file${NC}"
        return 1
    fi
    
    # 获取文件基础名称
    local base_name
    base_name=$(get_basename_without_ext "$input_file")
    echo -e "${GREEN}文件基础名: $base_name${NC}"
    echo ""

    # 检测协议
    if ! detect_protocols "$input_file"; then
        echo -e "${RED}协议检测失败，将跳过协议过滤${NC}"
    fi
    echo ""

    # 执行所有配置的 tshark 命令
    local cmd_count=0
    local success_count=0
    local fail_count=0
    local skip_count=0

    for cmd_config in "${TSHARK_COMMANDS[@]}"; do
        cmd_count=$((cmd_count + 1))

        # 分割命令配置（格式: 命令::后缀::协议）
        # 提取命令模板（第一个 :: 之前的部分）
        cmd_template="${cmd_config%%::*}"

        # 提取剩余部分（第一个 :: 之后）
        local remaining="${cmd_config#*::}"

        # 提取输出后缀（剩余部分的第一个 :: 之前，如果没有 :: 则是全部）
        if [[ "$remaining" =~ :: ]]; then
            output_suffix="${remaining%%::*}"
            required_protocol="${remaining#*::}"
        else
            output_suffix="$remaining"
            required_protocol=""
        fi

        echo -e "${BLUE}[命令 $cmd_count/${#TSHARK_COMMANDS[@]}]${NC}"

        # 传递序号和协议参数
        local exit_code=0
        execute_tshark_command "$input_file" "$cmd_template" "$output_suffix" "$output_dir" "$base_name" "$cmd_count" "$required_protocol"
        exit_code=$?

        if [ $exit_code -eq 0 ]; then
            success_count=$((success_count + 1))
        elif [ $exit_code -eq 2 ]; then
            skip_count=$((skip_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
        echo ""
    done
    
    # 显示该文件的处理总结
    echo -e "${BLUE}文件处理完成: $base_name${NC}"
    echo -e "  总命令数: $cmd_count"
    echo -e "  ${GREEN}成功: $success_count${NC}"
    if [ "$skip_count" -gt 0 ]; then
        echo -e "  ${YELLOW}跳过: $skip_count${NC}"
    else
        echo -e "  跳过: $skip_count"
    fi
    if [ "$fail_count" -gt 0 ]; then
        echo -e "  ${RED}失败: $fail_count${NC}"
    else
        echo -e "  失败: $fail_count"
    fi
    echo ""
    
    return 0
}

# ============================================
# 主程序
# ============================================

# 输入参数数组（可能包含文件、逗号分隔的列表或目录）
declare -a INPUT_ARGS=()
OUTPUT_DIR=""
CONFIG_FILE=""
USE_DEFAULT_OUTPUT=true
USE_DEFAULT_CONFIG=true

# 解析命令行参数
while getopts "i:c:o:h" opt; do
    case $opt in
        i)
            INPUT_ARGS+=("$OPTARG")
            ;;
        c)
            CONFIG_FILE="$OPTARG"
            USE_DEFAULT_CONFIG=false
            ;;
        o)
            OUTPUT_DIR="$OPTARG"
            USE_DEFAULT_OUTPUT=false
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

# 解析所有输入参数，构建最终的文件列表
declare -a INPUT_FILES=()
echo -e "${BLUE}解析输入参数...${NC}"

for input_arg in "${INPUT_ARGS[@]}"; do
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            INPUT_FILES+=("$file")
        fi
    done < <(parse_input_argument "$input_arg")
done

# 检查是否找到了任何文件
if [ ${#INPUT_FILES[@]} -eq 0 ]; then
    echo -e "${RED}错误: 未找到任何有效的 pcap/pcapng 文件${NC}" >&2
    exit 1
fi

echo -e "${GREEN}找到 ${#INPUT_FILES[@]} 个输入文件${NC}"
echo ""

# 检查 tshark 是否可用
if ! command -v tshark >/dev/null 2>&1; then
    echo -e "${RED}错误: 未找到 tshark 命令${NC}" >&2
    echo -e "${RED}请确保已安装 Wireshark/tshark${NC}" >&2
    exit 1
fi

# 加载配置文件
if [ "$USE_DEFAULT_CONFIG" = true ]; then
    # 使用默认配置文件
    # 首先在脚本所在目录查找
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$SCRIPT_DIR/$DEFAULT_CONFIG_FILE" ]; then
        CONFIG_FILE="$SCRIPT_DIR/$DEFAULT_CONFIG_FILE"
    elif [ -f "$DEFAULT_CONFIG_FILE" ]; then
        # 在当前目录查找
        CONFIG_FILE="$DEFAULT_CONFIG_FILE"
    else
        echo -e "${RED}错误: 未找到默认配置文件: $DEFAULT_CONFIG_FILE${NC}" >&2
        echo -e "${RED}请在脚本所在目录或当前目录创建配置文件，或使用 -c 参数指定配置文件${NC}" >&2
        exit 1
    fi
fi

# 加载配置文件中的命令
if ! load_config_file "$CONFIG_FILE"; then
    exit 1
fi
echo ""

# 如果使用默认输出目录，需要为每个文件确定其输出目录
# 这里先不创建，在处理每个文件时再创建
if [ "$USE_DEFAULT_OUTPUT" = false ]; then
    # 用户指定了输出目录，统一创建
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        echo -e "${RED}错误: 无法创建输出目录: $OUTPUT_DIR${NC}" >&2
        exit 1
    fi

    # 获取输出目录的绝对路径
    if ! OUTPUT_DIR_ABS=$(cd "$OUTPUT_DIR" && pwd); then
        echo -e "${RED}错误: 无法访问输出目录: $OUTPUT_DIR${NC}" >&2
        exit 1
    fi

    # 检查输出目录是否可写
    if [ ! -w "$OUTPUT_DIR_ABS" ]; then
        echo -e "${RED}错误: 输出目录不可写: $OUTPUT_DIR_ABS${NC}" >&2
        exit 1
    fi
fi

# 显示配置信息
echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}PCAP 分析脚本${NC}"
echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}配置文件: $CONFIG_FILE${NC}"
echo -e "${GREEN}配置的命令数: ${#TSHARK_COMMANDS[@]}${NC}"
echo -e "${GREEN}输入文件数量: ${#INPUT_FILES[@]}${NC}"
for i in "${!INPUT_FILES[@]}"; do
    echo -e "  [$((i+1))] ${INPUT_FILES[$i]}"
done

if [ "$USE_DEFAULT_OUTPUT" = true ]; then
    echo -e "${GREEN}输出模式: 默认（每个文件所在目录下的 statistics/ 子目录）${NC}"
else
    echo -e "${GREEN}输出目录: $OUTPUT_DIR_ABS${NC}"
fi

echo -e "${BLUE}=======================================${NC}"
echo ""

# 统计变量
total_files=0
processed_files=0
failed_files=0

# 处理每个输入文件
for input_file in "${INPUT_FILES[@]}"; do
    total_files=$((total_files + 1))

    # 确定该文件的输出目录
    local_output_dir=""
    if [ "$USE_DEFAULT_OUTPUT" = true ]; then
        # 使用默认输出目录（文件所在目录下的 statistics 子目录）
        local_output_dir=$(get_default_output_dir "$input_file")

        # 创建输出目录
        if ! mkdir -p "$local_output_dir" 2>/dev/null; then
            echo -e "${RED}错误: 无法创建输出目录: $local_output_dir${NC}" >&2
            failed_files=$((failed_files + 1))
            continue
        fi

        echo -e "${BLUE}输出目录: $local_output_dir${NC}"
    else
        # 使用用户指定的输出目录
        local_output_dir="$OUTPUT_DIR_ABS"
    fi

    if process_single_file "$input_file" "$local_output_dir"; then
        processed_files=$((processed_files + 1))
    else
        failed_files=$((failed_files + 1))
    fi
done

# 显示最终总结
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}执行总结${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "总文件数: $total_files"
echo -e "${GREEN}成功处理: $processed_files${NC}"
if [ "$failed_files" -gt 0 ]; then
    echo -e "${RED}处理失败: $failed_files${NC}"
else
    echo -e "处理失败: $failed_files"
fi
echo -e "${BLUE}========================================${NC}"

# 根据失败数量返回适当的退出码
if [ "$failed_files" -gt 0 ]; then
    exit 1
else
    exit 0
fi

