#!/bin/bash

# 暫存檔案
TEMP_DIR=$(mktemp -d)
WARNINGS_FILE="$TEMP_DIR/warnings.txt"
TIMER_FILE="$TEMP_DIR/timers.txt"
CRITICAL_FILE="$TEMP_DIR/critical.txt"
FINAL_OUTPUT="$TEMP_DIR/final_output.txt"
LOGS_DIR="$TEMP_DIR/device_logs"
IGNORE_TIMER_IDS="$TEMP_DIR/ignore_timer_ids.txt"
IGNORE_WARN_IDS="$TEMP_DIR/ignore_warn_ids.txt"

# 建立目錄儲存設備記錄
mkdir -p "$LOGS_DIR"

# 設定輸入檔
INPUT_FILE="/lpot/pci-config-changes.log"

# 初始化變數
CURRENT_TIME=""
DEVICE_ID=""
DEVICE_NAME=""

# 清空輸出檔案
> "$WARNINGS_FILE"
> "$TIMER_FILE"
> "$CRITICAL_FILE"
> "$FINAL_OUTPUT"
> "$IGNORE_TIMER_IDS"
> "$IGNORE_WARN_IDS"

# 逐行處理記錄檔
while IFS= read -r line; do
    # 解析時間戳記
    if [[ "$line" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
        CURRENT_TIME="${BASH_REMATCH[1]}"
    fi

    # 解析設備資訊
    if [[ "$line" =~ Device:\ +([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9]) ]]; then
        DEVICE_ID="${BASH_REMATCH[1]}"
        # 獲取簡短設備 ID 用於 lspci 命令
        SHORT_DEVICE_ID=$(echo "$DEVICE_ID" | sed 's/^0000://')
        
        # 使用 lspci 獲取設備名稱
        FULL_DEVICE_INFO=$(lspci -s "$SHORT_DEVICE_ID" 2>/dev/null)
        if [[ -n "$FULL_DEVICE_INFO" ]]; then
            # 提取設備名稱，去除前面的 ID 部分
            DEVICE_NAME=$(echo "$FULL_DEVICE_INFO" | sed "s/^$SHORT_DEVICE_ID //; s/^: //")
        else
            DEVICE_NAME="UNKNOWN"
        fi
        
        # 為每個設備創建目錄
        mkdir -p "$LOGS_DIR/$DEVICE_ID"
    fi

    # 解析 offset 變化
    if [[ "$line" =~ Value\ at\ offset\ (0x[0-9a-f]+)\ changed\ from\ (0x[0-9a-f]+)\ to\ (0x[0-9a-f]+) ]]; then
        OFFSET="${BASH_REMATCH[1]}"
        FROM_VALUE="${BASH_REMATCH[2]}"
        TO_VALUE="${BASH_REMATCH[3]}"
        
        # 記錄變化到設備特定的 offset 檔案
        echo "$CURRENT_TIME $FROM_VALUE $TO_VALUE" >> "$LOGS_DIR/$DEVICE_ID/$OFFSET"
    fi
done < "$INPUT_FILE"

# 創建一個紀錄所有出現過的offset的文件
find "$LOGS_DIR" -type f -name "0x*" | sed 's|.*/\(0x[0-9a-f]\+\)$|\1|' | sort | uniq > "$TEMP_DIR/all_offsets"

# 創建用於統計每個offset出現次數的文件
> "$TEMP_DIR/offset_counts"

# 步驟1: 找出所有timer裝置的ID並加入忽略列表
for DEVICE_DIR in "$LOGS_DIR"/*; do
    if [ -d "$DEVICE_DIR" ]; then
        DEVICE_ID=$(basename "$DEVICE_DIR")
        SHORT_DEVICE_ID=$(echo "$DEVICE_ID" | sed 's/^0000://')
        
        # 使用 lspci 獲取設備名稱
        FULL_DEVICE_INFO=$(lspci -s "$SHORT_DEVICE_ID" 2>/dev/null)
        if [[ -n "$FULL_DEVICE_INFO" ]]; then
            DEVICE_NAME=$(echo "$FULL_DEVICE_INFO" | sed "s/^$SHORT_DEVICE_ID //; s/^: //")
        else
            DEVICE_NAME="UNKNOWN"
        fi
        
        # 設備是否有timer標記
        DEVICE_HAS_TIMER=false
        
        # 處理該設備的每個 offset 檔案
        for OFFSET_FILE in "$DEVICE_DIR"/*; do
            if [ -f "$OFFSET_FILE" ]; then
                OFFSET=$(basename "$OFFSET_FILE")
                
                # 統計此offset出現的次數
                echo "$OFFSET" >> "$TEMP_DIR/offset_counts"
                
                # 檢查該 offset 的所有記錄
                # 首先檢查是否所有行都有相同的 FROM-TO 對
                FROM_TO_PAIRS=$(awk '{print $2"-"$3}' "$OFFSET_FILE" | sort | uniq)
                PAIR_COUNT=$(echo "$FROM_TO_PAIRS" | wc -l)
                
                if [ "$PAIR_COUNT" -eq 1 ]; then
                    # 所有記錄都有相同的FROM-TO對，忽略不顯示
                    continue
                fi
                
                # 檢查是否所有行都有相同的 FROM 值
                UNIQUE_FROM=$(awk '{print $2}' "$OFFSET_FILE" | sort | uniq)
                FROM_COUNT=$(echo "$UNIQUE_FROM" | wc -l)
                
                # ===== 修正後的timer判斷邏輯 =====
                # 條件1: 有多個不同的FROM值
                if [ "$FROM_COUNT" -gt 1 ]; then
                    echo "[Info] Device: $DEVICE_ID ($DEVICE_NAME) offset $OFFSET is timer!!! (multiple from values)" >> "$TIMER_FILE"
                    DEVICE_HAS_TIMER=true
                    continue
                fi
                
                # 條件2: 有單一FROM值，但有多個不同的TO值
                TO_VALUES=$(awk '{print $3}' "$OFFSET_FILE" | sort | uniq)
                TO_COUNT=$(echo "$TO_VALUES" | wc -l)
                
                # 如果TO值有多個（超過3個不同值或TO值占比超過50%的值不到2個），認為是timer
                if [ "$TO_COUNT" -gt 3 ]; then
                    echo "[Info] Device: $DEVICE_ID ($DEVICE_NAME) offset $OFFSET is timer!!! (multiple to values: $TO_COUNT unique values)" >> "$TIMER_FILE"
                    DEVICE_HAS_TIMER=true
                    continue
                fi
                
                # 獲取所有TO值並計算每個TO值的出現次數
                declare -A to_counts
                TOTAL_RECORDS=0
                while IFS= read -r record; do
                    TO=$(echo "$record" | awk '{print $3}')
                    ((to_counts["$TO"]++))
                    ((TOTAL_RECORDS++))
                done < "$OFFSET_FILE"
                
                # 檢查TO值的分布是否不規則
                # 計算TOP 2的TO值佔比
                sorted_counts=$(for to in "${!to_counts[@]}"; do echo "${to_counts[$to]} $to"; done | sort -nr)
                top_counts=$(echo "$sorted_counts" | head -2 | awk '{sum+=$1} END {print sum}')
                
                # 如果前兩個最常見的TO值加起來佔比小於80%，認為是timer
                if (( $(echo "scale=2; $top_counts / $TOTAL_RECORDS < 0.8" | bc -l) )); then
                    echo "[Info] Device: $DEVICE_ID ($DEVICE_NAME) offset $OFFSET is timer!!! (irregular to values)" >> "$TIMER_FILE"
                    DEVICE_HAS_TIMER=true
                    continue
                fi
            fi
        done
        
        # 如果設備有任何timer標記，將設備ID加入timer忽略列表
        if [ "$DEVICE_HAS_TIMER" = true ]; then
            echo "$DEVICE_ID" >> "$IGNORE_TIMER_IDS"
        fi
    fi
done

# 如果有timer設備，顯示timer訊息
if [ -s "$TIMER_FILE" ]; then
    sort -V "$TIMER_FILE" > "$TEMP_DIR/sorted_timers.txt"
    cat "$TEMP_DIR/sorted_timers.txt" >> "$FINAL_OUTPUT"
    echo "" >> "$FINAL_OUTPUT"  # 添加額外換行
fi

# 步驟2: 找出所有warning裝置的ID（排除已被標為timer的裝置）
for DEVICE_DIR in "$LOGS_DIR"/*; do
    if [ -d "$DEVICE_DIR" ]; then
        DEVICE_ID=$(basename "$DEVICE_DIR")
        
        # 檢查此設備是否已被標為timer
        if grep -q "^$DEVICE_ID$" "$IGNORE_TIMER_IDS"; then
            continue  # 跳過已經是timer的設備
        fi
        
        SHORT_DEVICE_ID=$(echo "$DEVICE_ID" | sed 's/^0000://')
        
        # 使用 lspci 獲取設備名稱
        FULL_DEVICE_INFO=$(lspci -s "$SHORT_DEVICE_ID" 2>/dev/null)
        if [[ -n "$FULL_DEVICE_INFO" ]]; then
            DEVICE_NAME=$(echo "$FULL_DEVICE_INFO" | sed "s/^$SHORT_DEVICE_ID //; s/^: //")
        else
            DEVICE_NAME="UNKNOWN"
        fi
        
        # 設備是否有warning標記
        DEVICE_HAS_WARNING=false
        
        # 處理該設備的每個 offset 檔案
        for OFFSET_FILE in "$DEVICE_DIR"/*; do
            if [ -f "$OFFSET_FILE" ]; then
                OFFSET=$(basename "$OFFSET_FILE")
                
                # 檢查該 offset 的所有記錄
                # 首先檢查是否所有行都有相同的 FROM-TO 對
                FROM_TO_PAIRS=$(awk '{print $2"-"$3}' "$OFFSET_FILE" | sort | uniq)
                PAIR_COUNT=$(echo "$FROM_TO_PAIRS" | wc -l)
                
                if [ "$PAIR_COUNT" -eq 1 ]; then
                    # 所有記錄都有相同的FROM-TO對，忽略不顯示
                    continue
                fi
                
                # 檢查是否所有行都有相同的 FROM 值
                UNIQUE_FROM=$(awk '{print $2}' "$OFFSET_FILE" | sort | uniq)
                FROM_COUNT=$(echo "$UNIQUE_FROM" | wc -l)
                
                if [ "$FROM_COUNT" -eq 1 ]; then
                    # FROM 值都相同
                    
                    # 獲取所有TO值並計算每個TO值的出現次數
                    declare -A to_counts
                    TOTAL_RECORDS=0
                    while IFS= read -r record; do
                        TO=$(echo "$record" | awk '{print $3}')
                        ((to_counts["$TO"]++))
                        ((TOTAL_RECORDS++))
                    done < "$OFFSET_FILE"
                    
                    # 找出最常見的TO值及其出現次數
                    max_count=0
                    most_common_to=""
                    for to in "${!to_counts[@]}"; do
                        if [ "${to_counts[$to]}" -gt "$max_count" ]; then
                            max_count=${to_counts[$to]}
                            most_common_to=$to
                        fi
                    done
                    
                    # 如果最常見的TO值占比大於80%，檢查是否有異常值
                    if (( $(echo "scale=2; $max_count / $TOTAL_RECORDS > 0.8" | bc -l) )); then
                        HAS_WARNING=false
                        
                        # 顯示與最常見TO值不同的異常值
                        FROM=$(echo "$UNIQUE_FROM")
                        while IFS= read -r record; do
                            TIME=$(echo "$record" | awk '{print $1}')
                            TO=$(echo "$record" | awk '{print $3}')
                            
                            if [ "$TO" != "$most_common_to" ]; then
                                echo "[WARN] Device: $DEVICE_ID ($DEVICE_NAME) offset $OFFSET changed from $FROM to $TO on $TIME" >> "$WARNINGS_FILE"
                                HAS_WARNING=true
                            fi
                        done < "$OFFSET_FILE"
                        
                        if [ "$HAS_WARNING" = true ]; then
                            DEVICE_HAS_WARNING=true
                        fi
                    fi
                fi
            fi
        done
        
        # 如果設備有任何warning標記，將設備ID加入warning設備清單
        if [ "$DEVICE_HAS_WARNING" = true ]; then
            echo "$DEVICE_ID" >> "$IGNORE_WARN_IDS"
        fi
    fi
done

# 如果有warning設備，顯示warning訊息
if [ -s "$WARNINGS_FILE" ]; then
    sort -V "$WARNINGS_FILE" > "$TEMP_DIR/sorted_warnings.txt"
    cat "$TEMP_DIR/sorted_warnings.txt" >> "$FINAL_OUTPUT"
    echo "" >> "$FINAL_OUTPUT"  # 添加額外換行
fi

# 步驟3: 找出所有critical裝置（排除已被標為timer或warning的裝置）
# 檢查只出現過一次的offset（邏輯4）
sort "$TEMP_DIR/offset_counts" | uniq -c | sort -n | while read count offset; do
    if [ "$count" -eq 1 ]; then
        # 找到只出現一次的offset所屬的設備
        DEVICE_OFFSET_FILE=$(find "$LOGS_DIR" -name "$offset")
        if [ -f "$DEVICE_OFFSET_FILE" ]; then
            DEVICE_ID=$(echo "$DEVICE_OFFSET_FILE" | awk -F/ '{print $(NF-1)}')

            # 檢查此設備是否已被標為timer或warning
            if grep -q "^$DEVICE_ID$" "$IGNORE_TIMER_IDS" || grep -q "^$DEVICE_ID$" "$IGNORE_WARN_IDS"; then
                continue  # 跳過已經是timer或warning的設備
            fi

            SHORT_DEVICE_ID=$(echo "$DEVICE_ID" | sed 's/^0000://')

            # 獲取設備名稱
            FULL_DEVICE_INFO=$(lspci -s "$SHORT_DEVICE_ID" 2>/dev/null)
            if [[ -n "$FULL_DEVICE_INFO" ]]; then
                DEVICE_NAME=$(echo "$FULL_DEVICE_INFO" | sed "s/^$SHORT_DEVICE_ID //; s/^: //")
            else
                DEVICE_NAME="UNKNOWN"
            fi

            # 檢查該offset文件中是否有多個不同的FROM-TO對
            FROM_TO_PAIRS=$(awk '{print $2"-"$3}' "$DEVICE_OFFSET_FILE" | sort | uniq)
            PAIR_COUNT=$(echo "$FROM_TO_PAIRS" | wc -l)

            # 只有當存在多個不同的FROM-TO對時才標記為CRITICAL
            if [ "$PAIR_COUNT" -gt 1 ]; then
                while IFS= read -r record; do
                    TIME=$(echo "$record" | awk '{print $1}')
                    FROM=$(echo "$record" | awk '{print $2}')
                    TO=$(echo "$record" | awk '{print $3}')

                    echo "[CRITICAL] Device: $DEVICE_ID ($DEVICE_NAME) offset $offset changed from $FROM to $TO on $TIME" >> "$CRITICAL_FILE"
                done < "$DEVICE_OFFSET_FILE"
            fi
        fi
    fi
done

# 如果有critical設備，顯示critical訊息
if [ -s "$CRITICAL_FILE" ]; then
    sort -V "$CRITICAL_FILE" > "$TEMP_DIR/sorted_critical.txt"
    cat "$TEMP_DIR/sorted_critical.txt" >> "$FINAL_OUTPUT"
fi

# 輸出最終結果
echo "$FINAL_OUTPUT" >> /lpot/reboot.log

# 清理臨時文件
rm -rf "$TEMP_DIR"
