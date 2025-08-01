#!/bin/bash

# 檢查是否以 root 權限執行
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# 確保 /lpot 目錄存在並設定正確權限
echo "Create /lpot..."
mkdir /lpot
chmod 755 /lpot
chown root:root /lpot

# 安裝 lpot 主程式
install -m 755 bin/lpot /usr/local/bin/lpot
install -m 755 bin/lpotscan /usr/local/bin/lpotscan
install -m 755 bin/configscan /usr/local/bin/configscan
install -m 755 scripts/configscan_log.sh /usr/local/bin/configscan_log.sh

# 檢查目標檔案是否存在與權限是否正確
check_file() {
    local file=$1
    local expected_perm="755"
    
    if [ ! -f "$file" ]; then
        echo "Error: $file not found"
        return 1
    fi
    
    local actual_perm=$(stat -c "%a" "$file")
    if [ "$actual_perm" != "$expected_perm" ]; then
        echo "Warning: $file permission (Current: $actual_perm, Expect: $expected_perm)"
        return 1
    fi
    
    return 0
}

# 檢查所有目標檔案
check_file "/usr/local/bin/lpot"
check_file "/usr/local/bin/lpotscan"
check_file "/usr/local/bin/configscan"
check_file "/usr/local/bin/configscan_log.sh"

# 總結結果
if [ $? -eq 0 ]; then
    echo "Setup done"
else
    echo "Something wrong, please check message log"
    exit 1
fi

scripts/setup.sh

# 檢查 /lpot 是否成功創建
if [ ! -d "/lpot" ]; then
   echo "Error: Failed to create /lpot directory" 1>&2
   exit 1
fi

# 启动新的 shell，并自动切换到 /lpot
echo "Installation complete."
echo "Starting new shell and changing directory to /lpot..."
exec bash -c "cd /lpot; $SHELL"

exit 0

