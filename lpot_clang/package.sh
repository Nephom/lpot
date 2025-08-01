#!/bin/bash

# 設定版本和打包目錄
VERSION=$(date +"%Y%m%d")
PACKAGE_NAME="lpot_${VERSION}"

# 創建臨時目錄
mkdir -p $PACKAGE_NAME/bin
mkdir -p $PACKAGE_NAME/scripts

# 複製程式和安裝腳本
cp lpot $PACKAGE_NAME/bin/
cp install.sh $PACKAGE_NAME/scripts/
cp configscan_log.sh $PACKAGE_NAME/scripts/
cp setup.sh $PACKAGE_NAME/scripts/
cp lpotscan $PACKAGE_NAME/bin/
cp configscan $PACKAGE_NAME/bin/

chmod +x $PACKAGE_NAME/scripts/install.sh
chmod +x $PACKAGE_NAME/scripts/setup.sh

# 製作 scexe 包（自解壓可執行檔）
makeself $PACKAGE_NAME $PACKAGE_NAME.run "LPOT Installation Package" ./scripts/install.sh

# 清理臨時目錄
rm -rf $PACKAGE_NAME

echo "打包完成：$PACKAGE_NAME.run"
