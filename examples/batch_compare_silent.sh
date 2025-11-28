#!/bin/bash
# 批量比较 PCAP 文件示例脚本
# 使用 --quiet 模式减少屏幕输出

set -e  # 遇到错误立即退出

# 配置
DB_CONNECTION="postgresql://postgres:password@172.16.200.156:5433/r2"
KASE_ID=133
OUTPUT_DIR="./comparison_results"
LOG_FILE="./batch_compare.log"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

# 清空日志文件
> "$LOG_FILE"

# 定义要比较的文件对
# 格式: "baseline_file:baseline_pcapid:compare_file:compare_pcapid:description"
declare -a FILE_PAIRS=(
    "baseline_v1.pcap:0:test_v1.pcap:1:Version 1 Comparison"
    "baseline_v2.pcap:0:test_v2.pcap:1:Version 2 Comparison"
    "baseline_v3.pcap:0:test_v3.pcap:1:Version 3 Comparison"
)

# 统计变量
TOTAL=${#FILE_PAIRS[@]}
SUCCESS=0
FAILED=0

echo "========================================" | tee -a "$LOG_FILE"
echo "Batch PCAP Comparison - Quiet Mode" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "Total pairs to process: $TOTAL" | tee -a "$LOG_FILE"
echo "Output directory: $OUTPUT_DIR" | tee -a "$LOG_FILE"
echo "Database: $DB_CONNECTION" | tee -a "$LOG_FILE"
echo "Case ID: $KASE_ID" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# 处理每一对文件
for i in "${!FILE_PAIRS[@]}"; do
    PAIR="${FILE_PAIRS[$i]}"
    IFS=':' read -r FILE1 PCAPID1 FILE2 PCAPID2 DESC <<< "$PAIR"
    
    NUM=$((i + 1))
    echo "[$NUM/$TOTAL] Processing: $DESC" | tee -a "$LOG_FILE"
    echo "  Baseline: $FILE1 (pcap_id=$PCAPID1)" | tee -a "$LOG_FILE"
    echo "  Compare:  $FILE2 (pcap_id=$PCAPID2)" | tee -a "$LOG_FILE"
    
    # 检查文件是否存在
    if [ ! -f "$FILE1" ]; then
        echo "  ❌ ERROR: Baseline file not found: $FILE1" | tee -a "$LOG_FILE"
        FAILED=$((FAILED + 1))
        echo "" | tee -a "$LOG_FILE"
        continue
    fi
    
    if [ ! -f "$FILE2" ]; then
        echo "  ❌ ERROR: Compare file not found: $FILE2" | tee -a "$LOG_FILE"
        FAILED=$((FAILED + 1))
        echo "" | tee -a "$LOG_FILE"
        continue
    fi
    
    # 生成输出文件名
    OUTPUT_FILE="$OUTPUT_DIR/result_${NUM}_$(basename ${FILE1%.pcap})_vs_$(basename ${FILE2%.pcap}).txt"
    
    # 执行比较（静默模式）
    START_TIME=$(date +%s)
    
    if capmaster compare \
        --file1 "$FILE1" \
        --file1-pcapid "$PCAPID1" \
        --file2 "$FILE2" \
        --file2-pcapid "$PCAPID2" \
        --quiet \
        -o "$OUTPUT_FILE" \
        --show-flow-hash \
        --db-connection "$DB_CONNECTION" \
        --kase-id "$KASE_ID" \
        2>> "$LOG_FILE"; then
        
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        
        # 检查输出文件大小
        if [ -f "$OUTPUT_FILE" ]; then
            FILE_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null)
            echo "  ✅ SUCCESS (${DURATION}s, ${FILE_SIZE} bytes)" | tee -a "$LOG_FILE"
            echo "  Output: $OUTPUT_FILE" | tee -a "$LOG_FILE"
            SUCCESS=$((SUCCESS + 1))
        else
            echo "  ⚠️  WARNING: Completed but output file not found" | tee -a "$LOG_FILE"
            FAILED=$((FAILED + 1))
        fi
    else
        END_TIME=$(date +%s)
        DURATION=$((END_TIME - START_TIME))
        echo "  ❌ FAILED (${DURATION}s)" | tee -a "$LOG_FILE"
        FAILED=$((FAILED + 1))
    fi
    
    echo "" | tee -a "$LOG_FILE"
done

# 输出总结
echo "========================================" | tee -a "$LOG_FILE"
echo "Batch Processing Summary" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "Total:   $TOTAL" | tee -a "$LOG_FILE"
echo "Success: $SUCCESS" | tee -a "$LOG_FILE"
echo "Failed:  $FAILED" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"

# 列出生成的文件
if [ $SUCCESS -gt 0 ]; then
    echo "" | tee -a "$LOG_FILE"
    echo "Generated files:" | tee -a "$LOG_FILE"
    ls -lh "$OUTPUT_DIR"/*.txt | tee -a "$LOG_FILE"
fi

# 退出码
if [ $FAILED -gt 0 ]; then
    echo "" | tee -a "$LOG_FILE"
    echo "⚠️  Some comparisons failed. Check $LOG_FILE for details." | tee -a "$LOG_FILE"
    exit 1
else
    echo "" | tee -a "$LOG_FILE"
    echo "✅ All comparisons completed successfully!" | tee -a "$LOG_FILE"
    exit 0
fi

