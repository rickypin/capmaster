#!/usr/bin/env bash
# match_tcp_conns.sh - TCP连接级跨捕获点匹配分析工具
# 支持NAT场景、header-only截断pcap、基于TCP/IP层指纹的连接匹配
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

usage() {
  cat <<'USAGE'
用法: bash match_tcp_conns.sh -i <input> [选项]

参数:
  -i <input>    输入目录（必须包含有且只有2个pcap/pcapng文件）
  -o <path>     输出目录路径（可选）
                - 如不指定，默认使用输入目录下的 statistics/ 子目录
  -h            显示此帮助信息

选项:
  --mode auto|full|header   匹配模式 (默认: auto)
                            auto: 自动检测header-only
                            full: 强制启用负载特征
                            header: 仅使用TCP/IP头部特征
  --bucket auto|server|port 分桶策略 (默认: auto)
                            auto: 自动检测最优策略 ⭐ 推荐
                            server: 按(server_ip, server_port)分桶
                            port: 仅按server_port分桶
  --sample auto|off|N       采样策略 (默认: auto)
                            auto: 连接数>1000时自动采样 ⭐ 推荐
                            off: 强制不采样
                            N: 强制采样到N个连接
  --topN N                  用于长度形状签名的包数量 (默认: 20)
  --len-sig N               长度形状签名token数上限 (默认: 12)
  --min-score N             最低匹配分数阈值 (默认: 0.60)

依赖: tshark >= 4.2, awk, sort, xxd, md5sum

示例:
  bash match_tcp_conns.sh -i cases/test/
  bash match_tcp_conns.sh -i cases/test/ -o output/
  bash match_tcp_conns.sh -i cases/test/ --mode header --min-score 0.70

说明:
  默认使用 --bucket auto 自动检测最优分桶策略:
  • 如果服务器IP完全相同 → 使用 server 分桶 (高精度)
  • 如果服务器IP不同但有共同端口 → 使用 port 分桶 (NAT/LB友好)
  • 如果没有共同端口 → 使用 server 分桶 (可能无法匹配)
USAGE
}

# 扫描目录中的 pcap/pcapng 文件（不包括子目录）
scan_directory_for_pcap() {
    local dir="$1"
    local -a found_files=()

    if [ ! -d "$dir" ]; then
        echo -e "${RED}错误: 不是有效的目录: $dir${NC}" >&2
        return 1
    fi

    # 查找 .pcap 和 .pcapng 文件（仅当前目录，不递归）
    while IFS= read -r -d '' file; do
        found_files+=("$file")
    done < <(find "$dir" -maxdepth 1 -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) -print0 2>/dev/null)

    if [ ${#found_files[@]} -eq 0 ]; then
        echo -e "${RED}错误: 目录中未找到 pcap/pcapng 文件: $dir${NC}" >&2
        return 1
    fi

    if [ ${#found_files[@]} -ne 2 ]; then
        echo -e "${RED}错误: 目录中必须有且只有2个 pcap/pcapng 文件，实际找到 ${#found_files[@]} 个${NC}" >&2
        echo -e "${YELLOW}找到的文件:${NC}" >&2
        for f in "${found_files[@]}"; do
            echo -e "  - $(basename "$f")" >&2
        done
        return 1
    fi

    # 输出找到的文件（每行一个）
    printf '%s\n' "${found_files[@]}"
    return 0
}

# 参数解析
INPUT_DIR=""
OUTPUT_DIR=""
USE_DEFAULT_OUTPUT=true

MODE="auto"
BUCKET="auto"  # 改为auto,自动检测
BUCKET_MANUAL=""  # 记录用户是否手动指定
SAMPLE="auto"  # 采样策略: auto|off|数字
TOPN=20
LENSIG=12
MIN_SCORE=0.60

# 解析命令行参数
while [[ $# -gt 0 ]]; do
  case "$1" in
    -i)
      INPUT_DIR="$2"
      shift 2
      ;;
    -o)
      OUTPUT_DIR="$2"
      USE_DEFAULT_OUTPUT=false
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --bucket)
      BUCKET="$2"
      BUCKET_MANUAL="yes"
      shift 2
      ;;
    --sample)
      SAMPLE="$2"
      shift 2
      ;;
    --topN)
      TOPN="$2"
      shift 2
      ;;
    --len-sig)
      LENSIG="$2"
      shift 2
      ;;
    --min-score)
      MIN_SCORE="$2"
      shift 2
      ;;
    *)
      echo -e "${RED}未知参数: $1${NC}" >&2
      usage
      exit 2
      ;;
  esac
done

# 检查必需参数
if [ -z "$INPUT_DIR" ]; then
    echo -e "${RED}错误: 必须指定输入目录 (-i)${NC}" >&2
    usage
    exit 1
fi

# 检查输入目录是否存在
if [ ! -d "$INPUT_DIR" ]; then
    echo -e "${RED}错误: 输入目录不存在: $INPUT_DIR${NC}" >&2
    exit 1
fi

# 扫描目录中的 pcap 文件
echo -e "${BLUE}扫描目录: $INPUT_DIR${NC}"
declare -a PCAP_FILES=()
while IFS= read -r file; do
    PCAP_FILES+=("$file")
done < <(scan_directory_for_pcap "$INPUT_DIR")

# 检查是否成功找到2个文件
if [ ${#PCAP_FILES[@]} -ne 2 ]; then
    echo -e "${RED}错误: 未能找到有效的2个 pcap/pcapng 文件${NC}" >&2
    exit 1
fi

A="${PCAP_FILES[0]}"
B="${PCAP_FILES[1]}"

echo -e "${GREEN}找到2个 pcap/pcapng 文件:${NC}"
echo -e "  A侧: $(basename "$A")"
echo -e "  B侧: $(basename "$B")"
echo ""

# 确定输出目录
if [ "$USE_DEFAULT_OUTPUT" = true ]; then
    # 使用默认输出目录（输入目录下的 statistics 子目录）
    OUTPUT_DIR="${INPUT_DIR}/statistics"
fi

# 创建输出目录
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

echo -e "${GREEN}输出目录: $OUTPUT_DIR_ABS${NC}"
echo ""

# 依赖检查
require() { 
  command -v "$1" >/dev/null 2>&1 || { 
    echo "错误: 缺少依赖工具 $1" >&2
    exit 3
  }
}

require tshark
require awk
require sort
require xxd
require md5sum

# tshark版本检查
TSV=$(tshark -v 2>&1 | head -1 | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]/) {print $i; exit}}')
if [[ -n "$TSV" ]]; then
  MAJOR="${TSV%%.*}"
  REST="${TSV#*.}"
  MINOR="${REST%%.*}"

  if [[ "${MAJOR:-0}" -lt 4 || ( "${MAJOR:-0}" -eq 4 && "${MINOR:-0}" -lt 2 ) ]]; then
    echo "警告: 建议使用 tshark >= 4.2, 当前版本: $TSV" >&2
  fi
else
  echo "警告: 无法检测tshark版本，继续执行..." >&2
fi

# 创建临时目录
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "=========================================="
echo "TCP连接级跨捕获点匹配分析"
echo "=========================================="
echo "A侧文件: $A"
echo "B侧文件: $B"
echo "匹配模式: $MODE"
if [[ "$BUCKET" == "auto" ]]; then
  echo "分桶策略: auto (自动检测)"
else
  echo "分桶策略: $BUCKET"
fi
echo "最低分数: $MIN_SCORE"
echo "=========================================="
echo ""

# 提取TCP报文字段
extract_fields() {
  local in="$1" out="$2"
  echo "[*] 正在提取 $in 的TCP报文字段..."
  
  tshark -r "$in" -Y "tcp" -o tcp.desegment_tcp_streams:false \
    -T fields -Eseparator=$'\t' \
    -e tcp.stream -e frame.number -e frame.time_epoch \
    -e ip.version -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
    -e tcp.flags.syn -e tcp.flags.ack -e tcp.seq -e tcp.ack -e tcp.len \
    -e tcp.window_size_value \
    -e tcp.options.mss_val -e tcp.options.wscale.shift -e tcp.options.sack_perm \
    -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr \
    -e ip.id -e ip.ttl -e ipv6.hlim \
    -e frame.cap_len -e frame.len \
    -e data.data \
    2>/dev/null | sort -t$'\t' -k1,1n -k2,2n > "$out"
  
  local pkt_count=$(wc -l < "$out")
  echo "    提取了 $pkt_count 个TCP报文"
}

extract_fields "$A" "$tmpdir/A.tsv"
extract_fields "$B" "$tmpdir/B.tsv"

echo ""

# 自动检测最优分桶策略
if [[ "$BUCKET" == "auto" ]]; then
  echo "[*] 正在自动检测最优分桶策略..."

  # 提取A侧的服务器IP:端口集合
  awk -F'\t' '
  {
    stream=$1; ips=$5; ipd=$6; ps=$7; pd=$8
    syn=$9; ackf=$10

    # 识别服务器端 (SYN包的目标 或 SYN-ACK包的源)
    if ((syn == "1" || syn == "True") && (ackf != "1" && ackf != "True")) {
      # SYN包: 目标是服务器
      if (!seen[stream]) {
        print ipd ":" pd
        seen[stream] = 1
      }
    } else if ((syn == "1" || syn == "True") && (ackf == "1" || ackf == "True")) {
      # SYN-ACK包: 源是服务器
      if (!seen[stream]) {
        print ips ":" ps
        seen[stream] = 1
      }
    }
  }
  ' "$tmpdir/A.tsv" | sort -u > "$tmpdir/A_servers.txt"

  # 提取B侧的服务器IP:端口集合
  awk -F'\t' '
  {
    stream=$1; ips=$5; ipd=$6; ps=$7; pd=$8
    syn=$9; ackf=$10

    if ((syn == "1" || syn == "True") && (ackf != "1" && ackf != "True")) {
      if (!seen[stream]) {
        print ipd ":" pd
        seen[stream] = 1
      }
    } else if ((syn == "1" || syn == "True") && (ackf == "1" || ackf == "True")) {
      if (!seen[stream]) {
        print ips ":" ps
        seen[stream] = 1
      }
    }
  }
  ' "$tmpdir/B.tsv" | sort -u > "$tmpdir/B_servers.txt"

  # 提取端口集合
  cut -d: -f2 "$tmpdir/A_servers.txt" | sort -u > "$tmpdir/A_ports.txt"
  cut -d: -f2 "$tmpdir/B_servers.txt" | sort -u > "$tmpdir/B_ports.txt"

  # 统计
  A_server_count=$(wc -l < "$tmpdir/A_servers.txt")
  B_server_count=$(wc -l < "$tmpdir/B_servers.txt")
  A_port_count=$(wc -l < "$tmpdir/A_ports.txt")
  B_port_count=$(wc -l < "$tmpdir/B_ports.txt")

  # 计算交集
  comm -12 "$tmpdir/A_servers.txt" "$tmpdir/B_servers.txt" > "$tmpdir/common_servers.txt"
  comm -12 "$tmpdir/A_ports.txt" "$tmpdir/B_ports.txt" > "$tmpdir/common_ports.txt"
  common_server_count=$(wc -l < "$tmpdir/common_servers.txt")
  common_port_count=$(wc -l < "$tmpdir/common_ports.txt")

  echo "    A侧服务器: $A_server_count 个, 端口: $A_port_count 个"
  echo "    B侧服务器: $B_server_count 个, 端口: $B_port_count 个"
  echo "    共同服务器: $common_server_count 个, 共同端口: $common_port_count 个"

  # 决策逻辑
  if [[ $common_server_count -gt 0 ]] && [[ $common_server_count -eq $A_server_count ]] && [[ $common_server_count -eq $B_server_count ]]; then
    # 服务器IP完全相同
    BUCKET="server"
    echo "    ✓ 决策: 使用 server 分桶 (服务器IP完全相同)"
  elif [[ $common_port_count -gt 0 ]]; then
    # 有共同端口,但服务器IP不同
    BUCKET="port"
    echo "    ✓ 决策: 使用 port 分桶 (服务器IP不同,但有共同端口)"
    if [[ $common_server_count -gt 0 ]]; then
      echo "    ℹ️  注意: 部分服务器IP相同($common_server_count/$A_server_count),但仍使用port分桶以覆盖所有连接"
    fi
  else
    # 没有共同端口
    BUCKET="server"
    echo "    ⚠️  警告: 没有共同端口,使用 server 分桶 (可能无法匹配)"
  fi

  echo ""
elif [[ -n "$BUCKET_MANUAL" ]]; then
  echo "[*] 使用用户指定的分桶策略: $BUCKET"
  echo ""
fi

# 构建连接特征表
build_conn_table() {
  local in="$1" side="$2" out="$3" topN="$4" lenSig="$5"
  
  echo "[*] 正在构建 $side 侧连接特征表..."
  
  awk -F'\t' -v TOPN="$topN" -v LENSIG="$lenSig" -v SIDE="$side" -v BUCKET="$BUCKET" '
  function md5hex(hex,  cmd, out) {
    if (hex == "" || hex == "-") return "";
    # 取前256字节计算MD5
    cmd = "echo \"" hex "\" | tr -d \"\\n\\r\" | xxd -r -p 2>/dev/null | head -c 256 | md5sum | awk '\''{print $1}'\''";
    cmd | getline out; close(cmd);
    return out;
  }
  
  function norm(x){ return x==""?"-":x }
  
  function synopt_str(mss,ws,sack,ts) { 
    return sprintf("mss=%s;ws=%s;sack=%s;ts=%s", mss, ws, sack, ts)
  }
  
  function cut_tokens(s, n,  i, a, out, cnt) {
    split(s, a, " ")
    out = ""
    cnt = 0
    for (i=1; i<=length(a) && cnt<n; i++) {
      if (a[i] == "") continue
      out = out (cnt?" ":"") a[i]
      cnt++
    }
    return out
  }
  
  function bucket_key(sip, spt) {
    if (BUCKET == "server") return sip":"spt
    else return spt
  }
  
  BEGIN {
    OFS = "\t"
    prev_stream = -1
  }
  
  {
    stream=$1; frno=$2; epoch=$3
    ipver=$4; ips=$5; ipd=$6; ps=$7; pd=$8
    syn=$9; ackf=$10; seq=$11; ack=$12; tlen=$13
    win=$14; mss=$15; wscale=$16; sack=$17; tsval=$18; tsecr=$19
    ipid=$20; ttl=$21; hlim=$22; caplen=$23; rlen=$24; data=$25
    
    # 新流开始
    if (stream != prev_stream) {
      # 输出上一个流
      if (prev_stream >= 0) {
        flush_stream()
      }
      
      # 重置状态
      reset_stream()
      prev_stream = stream
      first_sip = ips; first_sp = ps
      first_dip = ipd; first_dp = pd
    }
    
    total_cnt++
    if (caplen != "" && rlen != "" && caplen < rlen) cap_bad_cnt++
    
    # 识别握手 (tshark输出True/False)
    if ((syn == "1" || syn == "True") && (ackf != "1" && ackf != "True") && !seen_syn) {
      client_ip = ips; client_port = ps
      server_ip = ipd; server_port = pd
      synopt = synopt_str(norm(mss), norm(wscale), (sack==""?"0":sack), (tsval==""?"0":"1"))
      isn_c = norm(seq)
      ts0 = norm(tsval)
      te0 = norm(tsecr)
      seen_syn = 1
    }

    # SYN-ACK
    if ((syn == "1" || syn == "True") && (ackf == "1" || ackf == "True") && seen_syn && !seen_synack) {
      isn_s = norm(seq)
      seen_synack = 1
    }
    
    # 确定方向
    if (client_ip != "" && server_ip != "") {
      dir = (ips == client_ip && ps == client_port) ? "C" : "S"
    } else {
      dir = first ? "C" : "S"
    }
    
    # 长度形状签名
    if (tlen != "" && tlen > 0) {
      lensig = lensig sprintf("%s:%s ", dir, tlen)
    }
    
    # 记录首个IPID/TTL
    if (ipid0 == "-" && ipid != "") ipid0 = ipid
    if (ttl0 == "-") ttl0 = (ttl != "" ? ttl : (hlim != "" ? hlim : "-"))
    
    # 首个负载MD5
    if (data != "" && tlen > 0) {
      if (dir == "C" && data_c_md5 == "-") data_c_md5 = md5hex(data)
      if (dir == "S" && data_s_md5 == "-") data_s_md5 = md5hex(data)
    }
    
    first = 0
  }
  
  END {
    if (prev_stream >= 0) {
      flush_stream()
    }
  }
  
  function reset_stream() {
    total_cnt = 0; cap_bad_cnt = 0; lensig = ""
    synopt = "-"; isn_c = "-"; isn_s = "-"
    ts0 = "-"; te0 = "-"
    data_c_md5 = "-"; data_s_md5 = "-"
    ipid0 = "-"; ttl0 = "-"
    client_ip = ""; client_port = ""
    server_ip = ""; server_port = ""
    seen_syn = 0; seen_synack = 0; no_syn = 0
    first = 1
  }
  
  function flush_stream() {
    header_only = (cap_bad_cnt > 0 && cap_bad_cnt * 1.0 / total_cnt >= 0.80) ? 1 : 0
    lensig_cut = cut_tokens(lensig, LENSIG)
    
    # 如果没有握手信息，使用首包方向
    if (server_ip == "" || server_port == "") {
      server_ip = first_dip; server_port = first_dp
      client_ip = first_sip; client_port = first_sp
      no_syn = 1
    }
    
    five = client_ip ":" client_port " -> " server_ip ":" server_port
    bkey = bucket_key(server_ip, server_port)
    
    print SIDE "-" prev_stream, bkey, five, synopt, isn_c, isn_s, ts0, te0, \
          data_c_md5, data_s_md5, lensig_cut, ipid0, ttl0, header_only, no_syn
  }
  ' "$in" > "$out"
  
  local conn_count=$(wc -l < "$out")
  echo "    识别了 $conn_count 个TCP连接"
}

build_conn_table "$tmpdir/A.tsv" "A" "$tmpdir/A_conn.tsv" "$TOPN" "$LENSIG"
build_conn_table "$tmpdir/B.tsv" "B" "$tmpdir/B_conn.tsv" "$TOPN" "$LENSIG"

echo ""

# 采样函数: 时间分层采样 + 异常连接保护
sample_connections() {
  local in="$1" side="$2" out="$3" target_count="$4"

  local total_count=$(wc -l < "$in")

  # 如果连接数小于等于目标数,直接复制
  if [[ $total_count -le $target_count ]]; then
    cp "$in" "$out"
    echo "0" # 返回0表示未采样
    return
  fi

  echo "[*] 正在对 $side 侧进行采样 (总连接数: $total_count → 目标: $target_count)..." >&2

  # 使用awk进行时间分层采样
  awk -F'\t' -v TARGET="$target_count" -v TOTAL="$total_count" -v SIDE="$side" '
  BEGIN {
    srand()
    OFS = "\t"

    # 采样参数
    TIME_BUCKETS = 20  # 时间分层数
    OUTLIER_PKT_MIN = 3    # 报文数下限 (调整为3,更严格)
    OUTLIER_PKT_MAX = 500  # 报文数上限 (调整为500,更合理)
    OUTLIER_RATIO = 0.05   # 异常连接最多占目标采样数的5%

    conn_idx = 0
  }

  # 第一遍: 读取所有连接,识别异常连接
  NR == FNR {
    conn_idx++
    conn_id = $1
    five = $3
    lensig = $11

    # 统计报文数 (从长度形状签名中计算)
    pkt_count = 0
    if (lensig != "-") {
      split(lensig, tokens, " ")
      pkt_count = length(tokens)
    }

    # 存储连接信息
    conns[conn_idx] = $0
    pkt_counts[conn_idx] = pkt_count

    # 收集所有报文数用于统计
    all_pkt_counts[conn_idx] = pkt_count

    next
  }

  # 第二遍: 从原始TSV提取时间信息
  {
    stream = $1
    epoch = $3

    if (stream != prev_stream) {
      if (prev_stream != "") {
        # 记录上一个流的首包时间
        stream_times[prev_stream] = first_epoch
      }
      first_epoch = epoch
      prev_stream = stream
    }
  }

  END {
    # 记录最后一个流
    if (prev_stream != "") {
      stream_times[prev_stream] = first_epoch
    }

    # 为每个连接分配时间
    for (i = 1; i <= conn_idx; i++) {
      split(conns[i], fields, "\t")
      conn_id = fields[1]

      # 从conn_id中提取stream编号 (格式: A-123 或 B-456)
      split(conn_id, parts, "-")
      stream_num = parts[2]

      conn_times[i] = stream_times[stream_num]

      # 统计时间范围
      if (min_time == "" || conn_times[i] < min_time) min_time = conn_times[i]
      if (max_time == "" || conn_times[i] > max_time) max_time = conn_times[i]
    }

    # 识别异常连接: 使用固定阈值,但限制异常连接数量
    outlier_count = 0
    max_outliers = int(TARGET * OUTLIER_RATIO + 0.5)
    if (max_outliers < 5) max_outliers = 5  # 至少保留5个异常连接

    # 先识别极端异常 (报文数<=3)
    for (i = 1; i <= conn_idx; i++) {
      pkt = all_pkt_counts[i]
      if (pkt > 0 && pkt <= OUTLIER_PKT_MIN) {
        outliers[i] = 1
        outlier_count++
      }
    }

    # 如果还有配额,识别报文数过多的连接
    if (outlier_count < max_outliers) {
      for (i = 1; i <= conn_idx; i++) {
        if (outliers[i]) continue  # 已标记为异常
        pkt = all_pkt_counts[i]
        if (pkt >= OUTLIER_PKT_MAX) {
          outliers[i] = 1
          outlier_count++
          if (outlier_count >= max_outliers) break
        }
      }
    }

    # 输出异常连接统计
    printf("    异常连接识别: %d 个 (报文数<=%d 或 >=%d, 上限=%d)\n",
           outlier_count, OUTLIER_PKT_MIN, OUTLIER_PKT_MAX, max_outliers) > "/dev/stderr"
    printf("    时间范围: %.3f ~ %.3f (跨度: %.2f秒)\n", min_time, max_time, max_time - min_time) > "/dev/stderr"

    # 计算正常连接的采样数
    normal_count = conn_idx - outlier_count
    normal_target = TARGET - outlier_count

    if (normal_target < 0) normal_target = 0

    printf("    正常连接: %d 个, 采样目标: %d 个\n", normal_count, normal_target) > "/dev/stderr"

    # 时间分层采样
    time_span = max_time - min_time
    if (time_span <= 0) time_span = 1

    bucket_width = time_span / TIME_BUCKETS

    # 将正常连接分配到时间桶
    for (i = 1; i <= conn_idx; i++) {
      if (outliers[i]) continue

      bucket_id = int((conn_times[i] - min_time) / bucket_width)
      if (bucket_id >= TIME_BUCKETS) bucket_id = TIME_BUCKETS - 1

      time_buckets[bucket_id, ++time_bucket_counts[bucket_id]] = i
    }

    # 从每个时间桶中采样
    sampled_count = 0
    delete sampled

    # 先保留所有异常连接
    for (i = 1; i <= conn_idx; i++) {
      if (outliers[i]) {
        sampled[i] = 1
        sampled_count++
      }
    }

    # 从每个时间桶中按比例采样
    for (b = 0; b < TIME_BUCKETS; b++) {
      bucket_size = time_bucket_counts[b]
      if (bucket_size == 0) continue

      # 计算该桶应采样的数量
      bucket_target = int(normal_target * bucket_size / normal_count + 0.5)
      if (bucket_target > bucket_size) bucket_target = bucket_size

      # 随机采样
      if (bucket_target >= bucket_size) {
        # 全部保留
        for (j = 1; j <= bucket_size; j++) {
          idx = time_buckets[b, j]
          sampled[idx] = 1
          sampled_count++
        }
      } else {
        # 随机采样
        delete selected
        selected_count = 0

        while (selected_count < bucket_target) {
          rand_idx = int(rand() * bucket_size) + 1
          if (!selected[rand_idx]) {
            selected[rand_idx] = 1
            selected_count++
            idx = time_buckets[b, rand_idx]
            sampled[idx] = 1
            sampled_count++
          }
        }
      }
    }

    # 输出采样结果
    printf("    采样完成: %d 个连接 (采样率: %.1f%%)\n", sampled_count, sampled_count * 100.0 / conn_idx) > "/dev/stderr"

    # 按原始顺序输出采样后的连接
    for (i = 1; i <= conn_idx; i++) {
      if (sampled[i]) {
        print conns[i]
      }
    }
  }
  ' "$in" "$tmpdir/${side}.tsv" > "$out"

  echo "1" # 返回1表示已采样
}

# 决定是否采样
A_count=$(wc -l < "$tmpdir/A_conn.tsv")
B_count=$(wc -l < "$tmpdir/B_conn.tsv")

SAMPLE_ENABLED=0
A_SAMPLED=0
B_SAMPLED=0

if [[ "$SAMPLE" == "off" ]]; then
  echo "[*] 采样已禁用 (--sample off)"
  cp "$tmpdir/A_conn.tsv" "$tmpdir/A_final.tsv"
  cp "$tmpdir/B_conn.tsv" "$tmpdir/B_final.tsv"
elif [[ "$SAMPLE" == "auto" ]]; then
  # 自动判断: 连接数>1000时启用采样
  if [[ $A_count -gt 1000 || $B_count -gt 1000 ]]; then
    SAMPLE_ENABLED=1
    echo "[*] 自动启用采样策略 (连接数超过阈值)"

    # 计算目标采样数: 按10%比例,分段设置上限
    # 1001-10000: 10% (100-1000个)
    # 10001-30000: 10% (1001-3000个)
    # >30000: 最多3000个 (保持性能)
    A_TARGET=$(awk -v count="$A_count" 'BEGIN {
      target = int(count * 0.10 + 0.5)
      if (target < 100) target = 100
      if (count > 30000 && target > 3000) target = 3000
      print target
    }')

    B_TARGET=$(awk -v count="$B_count" 'BEGIN {
      target = int(count * 0.10 + 0.5)
      if (target < 100) target = 100
      if (count > 30000 && target > 3000) target = 3000
      print target
    }')

    A_SAMPLED=$(sample_connections "$tmpdir/A_conn.tsv" "A" "$tmpdir/A_final.tsv" "$A_TARGET")
    B_SAMPLED=$(sample_connections "$tmpdir/B_conn.tsv" "B" "$tmpdir/B_final.tsv" "$B_TARGET")
  else
    echo "[*] 连接数未超过阈值,不启用采样"
    cp "$tmpdir/A_conn.tsv" "$tmpdir/A_final.tsv"
    cp "$tmpdir/B_conn.tsv" "$tmpdir/B_final.tsv"
  fi
elif [[ "$SAMPLE" =~ ^[0-9]+$ ]]; then
  # 强制采样到指定数量
  SAMPLE_ENABLED=1
  TARGET="$SAMPLE"
  echo "[*] 强制采样到 $TARGET 个连接"

  A_SAMPLED=$(sample_connections "$tmpdir/A_conn.tsv" "A" "$tmpdir/A_final.tsv" "$TARGET")
  B_SAMPLED=$(sample_connections "$tmpdir/B_conn.tsv" "B" "$tmpdir/B_final.tsv" "$TARGET")
else
  echo "错误: 无效的采样参数: $SAMPLE" >&2
  exit 2
fi

# 输出采样统计
if [[ $SAMPLE_ENABLED -eq 1 ]]; then
  A_final=$(wc -l < "$tmpdir/A_final.tsv")
  B_final=$(wc -l < "$tmpdir/B_final.tsv")

  echo ""
  echo "=========================================="
  echo "采样统计"
  echo "=========================================="
  if [[ $A_SAMPLED -eq 1 ]]; then
    A_rate=$(awk -v final="$A_final" -v total="$A_count" 'BEGIN {printf "%.1f%%", final * 100.0 / total}')
    echo "A侧: $A_count → $A_final 连接 (采样率: $A_rate)"
  else
    echo "A侧: $A_count 连接 (未采样)"
  fi

  if [[ $B_SAMPLED -eq 1 ]]; then
    B_rate=$(awk -v final="$B_final" -v total="$B_count" 'BEGIN {printf "%.1f%%", final * 100.0 / total}')
    echo "B侧: $B_count → $B_final 连接 (采样率: $B_rate)"
  else
    echo "B侧: $B_count 连接 (未采样)"
  fi
  echo "=========================================="
fi

echo ""
echo "[*] 正在进行连接匹配..."

# 准备分桶数据 (使用采样后的连接表)
awk -F'\t' '{print $2"\t"$0}' "$tmpdir/A_final.tsv" | sort -t$'\t' -k1,1 > "$tmpdir/A_bucket.tsv"
awk -F'\t' '{print $2"\t"$0}' "$tmpdir/B_final.tsv" | sort -t$'\t' -k1,1 > "$tmpdir/B_bucket.tsv"

# 统计分桶信息
total_buckets=$(cut -f1 "$tmpdir/A_bucket.tsv" | sort -u | wc -l | tr -d ' ')
echo "    共 $total_buckets 个分桶待处理"
echo ""

# 执行匹配并输出到文件
OUTPUT_FILE="${OUTPUT_DIR_ABS}/correlations.txt"
echo -e "${BLUE}输出文件: $OUTPUT_FILE${NC}"
echo ""

awk -F'\t' -v MODE="$MODE" -v MIN_SCORE="$MIN_SCORE" -v TOTAL_BUCKETS="$total_buckets" '
function lensig_sim(a, b,   i, j, sa, sb, x, ua, ub, inter, uni) {
  if (a == "-" || b == "-") return 0
  split(a, sa, " ")
  split(b, sb, " ")

  # 构建集合
  for (i in sa) {
    x = sa[i]
    if (x != "") ua[x] = 1
  }
  for (j in sb) {
    x = sb[j]
    if (x != "") ub[x] = 1
  }

  # 计算Jaccard相似度
  inter = 0
  uni = 0
  for (x in ua) {
    if (ub[x]) inter++
    uni++
  }
  for (x in ub) {
    if (!ua[x]) uni++
  }

  if (uni == 0) return 0
  return inter / uni
}

function eq(a, b) {
  return (a != "" && a != "-" && b != "" && b != "-" && a == b) ? 1 : 0
}

function avail_add(v, w) {
  return (v != "" && v != "-") ? w : 0
}

function score_pair(A, B,   s, raw, avail, evi, sim, headerA, headerB, use_payload,
                    nA, AA, nB, BB, a, b,
                    synA, icA, isA, tsA, teA, dcA, dsA, lsA, ipidA, ttlA, hA,
                    synB, icB, isB, tsB, teB, dcB, dsB, lsB, ipidB, ttlB, hB,
                    w_syn, w_ic, w_is, w_dc, w_ds, w_ts, w_ls, w_ipidttl) {

  split(A, AA, "\t")
  split(B, BB, "\t")

  # 分桶数据格式: bucket \t conn_id \t bucket \t five \t ...
  # 所以实际数据从索引2开始,但第一个bucket字段已经在AA[1]了
  # 实际字段: 1:bucket 2:conn_id 3:bucket(重复) 4:five 5:synopt 6:isn_c 7:isn_s
  #           8:ts0 9:te0 10:data_c 11:data_s 12:lensig 13:ipid0 14:ttl0 15:header_only 16:no_syn
  synA = AA[5]; icA = AA[6]; isA = AA[7]; tsA = AA[8]; teA = AA[9]
  dcA = AA[10]; dsA = AA[11]; lsA = AA[12]; ipidA = AA[13]; ttlA = AA[14]; hA = AA[15]

  synB = BB[5]; icB = BB[6]; isB = BB[7]; tsB = BB[8]; teB = BB[9]
  dcB = BB[10]; dsB = BB[11]; lsB = BB[12]; ipidB = BB[13]; ttlB = BB[14]; hB = BB[15]

  headerA = (hA == "1")
  headerB = (hB == "1")

  # 确定是否使用负载特征
  if (MODE == "full") use_payload = 1
  else if (MODE == "header") use_payload = 0
  else use_payload = (!headerA && !headerB)

  raw = 0
  avail = 0
  evi = ""

  # 权重配置 (方案B: IPID作为必要条件,其他特征重新分配权重)
  w_syn = 0.25      # SYN选项序列 (从0.20提升到0.25)
  w_ic = 0.12       # 客户端ISN (从0.15降到0.12,降低不可靠特征权重)
  w_is = 0.06       # 服务器ISN (从0.08降到0.06,降低不可靠特征权重)
  w_dc = 0.15       # 客户端首包负载 (从0.18降到0.15,降低不可靠特征权重)
  w_ds = 0.08       # 服务器首包负载 (从0.10降到0.08,降低不可靠特征权重)
  w_ts = 0.10       # TCP时间戳 (从0.07提升到0.10)
  w_ls = 0.08       # 长度形状签名 (从0.15降到0.08,降低不可靠特征权重)
  w_ipid = 0.16     # IPID匹配 (新增,作为必要条件的额外加分)
  # 总计: 1.00
  # 注意: IPID是必要条件,没有IPID直接返回0分

  # 1. SYN选项序列匹配
  if (synA != "-" && synB != "-") {
    avail += w_syn
    if (eq(synA, synB)) {
      raw += w_syn
      evi = evi "synopt "
    }
  }

  # 2. 客户端ISN匹配
  if (icA != "-" && icB != "-") {
    avail += w_ic
    if (eq(icA, icB)) {
      raw += w_ic
      evi = evi "isnC "
    }
  }

  # 3. 服务器ISN匹配
  if (isA != "-" && isB != "-") {
    avail += w_is
    if (eq(isA, isB)) {
      raw += w_is
      evi = evi "isnS "
    }
  }

  # 4. TCP时间戳匹配
  if ((tsA != "" && tsA != "-") || (tsB != "" && tsB != "-")) {
    avail += w_ts
    if (eq(tsA, tsB) || eq(teA, teB)) {
      raw += w_ts
      evi = evi "ts "
    }
  }

  # 5. 负载哈希匹配
  if (use_payload) {
    if (dcA != "-" && dcB != "-") {
      avail += w_dc
      if (eq(dcA, dcB)) {
        raw += w_dc
        evi = evi "dataC "
      }
    }

    if (dsA != "-" && dsB != "-") {
      avail += w_ds
      if (eq(dsA, dsB)) {
        raw += w_ds
        evi = evi "dataS "
      }
    }
  }

  # 6. 长度形状签名匹配
  sim = lensig_sim(lsA, lsB)
  if (lsA != "-" && lsB != "-") {
    avail += w_ls
    if (sim >= 0.6) {
      raw += w_ls
      evi = evi sprintf("shape(%.2f) ", sim)
    }
  }

  # 7. IPID匹配 (必要条件)
  # 注意: TTL在NAT场景下会变化,不用于匹配,仅用于方向识别
  ipid_match = 0
  if (ipidA != "" && ipidA != "-" && ipidB != "" && ipidB != "-") {
    if (eq(ipidA, ipidB)) {
      ipid_match = 1
      avail += w_ipid
      raw += w_ipid
      evi = evi "ipid "
    }
  }

  # 方案B: IPID作为必要条件
  # 没有IPID匹配,直接返回0分,拒绝该匹配
  if (!ipid_match) {
    return "0\t0\tno-ipid"
  }

  if (avail <= 0) return "0\t0\t"
  s = raw / avail
  return s "\t" avail "\t" evi
}

# 快速排序函数 (降序)
function quicksort(arr, scores, left, right,   i, j, pivot, tmp) {
  if (left >= right) return

  # 选择中间元素作为pivot
  pivot = scores[arr[int((left + right) / 2)]]
  i = left
  j = right

  while (i <= j) {
    while (scores[arr[i]] > pivot) i++
    while (scores[arr[j]] < pivot) j--

    if (i <= j) {
      tmp = arr[i]
      arr[i] = arr[j]
      arr[j] = tmp
      i++
      j--
    }
  }

  if (left < j) quicksort(arr, scores, left, j)
  if (i < right) quicksort(arr, scores, i, right)
}

# 读取两侧数据到内存
FNR == NR {
  bucket = $1
  line = $0
  Aarr[bucket, ++Acnt[bucket]] = line
  next
}

{
  bucket = $1
  line = $0
  Barr[bucket, ++Bcnt[bucket]] = line
}

END {
  # 输出表头
  printf("========================================\n") > "/dev/stderr"
  printf("匹配结果 (A侧 ↔ B侧)\n") > "/dev/stderr"
  printf("========================================\n\n") > "/dev/stderr"

  total_matches = 0

  # 统计总桶数用于进度显示
  bucket_count = 0
  for (bucket in Acnt) {
    if (bucket in Bcnt) bucket_count++
  }

  processed_buckets = 0

  # 遍历每个桶
  for (bucket in Acnt) {
    if (!(bucket in Bcnt)) continue

    na = Acnt[bucket]
    nb = Bcnt[bucket]

    processed_buckets++

    # 显示进度 (每处理一个桶或大桶时显示)
    if (bucket_count <= 20 || processed_buckets % int(bucket_count/20 + 1) == 0 || na * nb > 10000) {
      printf("    进度: %d/%d 分桶 (当前桶: %s, A侧=%d, B侧=%d, 待评分=%d对)\n",
             processed_buckets, bucket_count, bucket, na, nb, na*nb) > "/dev/stderr"
      fflush("/dev/stderr")
    }

    # 计算所有候选对的评分
    candN = 0
    delete Score
    delete Evid
    delete cand

    total_pairs = na * nb
    processed_pairs = 0
    last_progress_pct = 0

    for (i = 1; i <= na; i++) {
      for (j = 1; j <= nb; j++) {
        a = Aarr[bucket, i]
        b = Barr[bucket, j]

        # 评分
        s = score_pair(a, b)
        split(s, ss, "\t")
        score = ss[1] + 0
        avail = ss[2] + 0
        evi = ss[3]

        if (score >= MIN_SCORE) {
          key = a "||" b
          Score[key] = score
          Evid[key] = evi
          cand[++candN] = key
        }

        # 对于大桶,显示更细粒度的进度 (每10%或每100万对)
        processed_pairs++
        if (total_pairs > 100000) {
          progress_pct = int(processed_pairs * 100 / total_pairs)
          if (progress_pct >= last_progress_pct + 10 || processed_pairs % 1000000 == 0) {
            printf("    进度: %d/%d 分桶 | 桶 %s: %d%% (%d/%d对, 已匹配候选=%d)\n",
                   processed_buckets, bucket_count, bucket, progress_pct,
                   processed_pairs, total_pairs, candN) > "/dev/stderr"
            fflush("/dev/stderr")
            last_progress_pct = progress_pct
          }
        }
      }
    }

    # 贪心一一匹配（按分数降序）
    # 使用快速排序替代冒泡排序以提升性能
    if (candN > 0) {
      printf("    正在对 %d 个候选匹配进行排序...\n", candN) > "/dev/stderr"
      fflush("/dev/stderr")
      quicksort(cand, Score, 1, candN)
      printf("    排序完成，开始输出匹配结果\n") > "/dev/stderr"
      fflush("/dev/stderr")
    }

    delete usedA
    delete usedB

    for (k = 1; k <= candN; k++) {
      key = cand[k]
      split(key, parts, "\\|\\|")
      a = parts[1]
      b = parts[2]

      split(a, aa, "\t")
      split(b, bb, "\t")

      # 分桶数据格式: bucket \t conn_id \t bucket \t five \t ...
      Aid = aa[2]
      Afive = aa[4]
      Bid = bb[2]
      Bfive = bb[4]

      if (usedA[Aid] || usedB[Bid]) continue

      usedA[Aid] = 1
      usedB[Bid] = 1
      total_matches++

      printf("[%d] A: %s\n", total_matches, Afive)
      printf("    B: %s\n", Bfive)
      printf("    置信度: %.2f | 证据: %s\n\n", Score[key], Evid[key])
    }
  }

  printf("========================================\n")
  printf("总计匹配: %d 对TCP连接\n", total_matches)
  printf("========================================\n")

  # 如果没有匹配且使用的是server分桶,给出提示
  if (total_matches == 0 && BUCKET == "server") {
    printf("\n")
    printf("💡 提示: 未找到匹配的连接。\n")
    printf("   如果这是NAT/负载均衡场景(服务器IP可能不同),\n")
    printf("   请尝试使用: --bucket port\n")
  }
}
' BUCKET="$BUCKET" "$tmpdir/A_bucket.tsv" "$tmpdir/B_bucket.tsv" | tee "$OUTPUT_FILE"

echo ""
echo -e "${GREEN}[*] 分析完成${NC}"
echo -e "${GREEN}结果已保存到: $OUTPUT_FILE${NC}"

