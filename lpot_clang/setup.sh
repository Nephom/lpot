#!/bin/bash

osname=$(awk -F= '/^NAME/{print $2}' /etc/os-release | tr -d '"')
osversion=$(awk -F= '/^VERSION_ID/{print $2}' /etc/os-release | tr -d '"')

if [[ "$osname" =~ "Red" ]]; then
    # RHEL 系統配置
    OSN="RHEL$osversion"
    echo -e "\033[34m\t\tRHEL System Detected: $OSN\033[m"
    echo -e "\033[34m\t\tDisabling Firewalld...\033[m"
    systemctl disable firewalld
    systemctl stop firewalld

    # 檢查是否已設置 autologin
    if grep -q "AutomaticLoginEnable=true" /etc/gdm/custom.conf 2>/dev/null; then
        echo -e "\033[33m\t\tAuto login already configured, skipping...\033[m"
    else
        echo -e "\033[34m\t\tSetting up Auto Login for root...\033[m"
        sed -i '/\[daemon\]/d' /etc/gdm/custom.conf
        cat << EOF >> /etc/gdm/custom.conf
[daemon]
AutomaticLoginEnable=true
AutomaticLogin=root
EOF
    fi

elif [[ "$osname" =~ "SLES" ]]; then
    # SLES 系統配置
    osv=$(awk -F= '/VERSION_ID/{print $2}' /etc/os-release | tr -d '"' | awk -F'.' '{print $1}')
    spv=$(awk -F= '/VERSION_ID/{print $2}' /etc/os-release | tr -d '"' | awk -F'.' '{print $2}')
    [ "$spv" ] && OSN="SLES${osv}SP${spv}" || OSN="SLES${osv}"
    echo -e "\033[34m\t\tSLES System Detected: $OSN\033[m"

    echo -e "\033[34m\t\tInstalling Required Packages...\033[m"
    zypper install -y insserv lsb-release at net-tools-deprecated > /dev/null 2>&1

    # 檢查是否已設置 autologin
    current_autologin=$(grep "DISPLAYMANAGER_AUTOLOGIN=" /etc/sysconfig/displaymanager 2>/dev/null | cut -d'"' -f2)
    if [[ -n "$current_autologin" && "$current_autologin" != "" ]]; then
        echo -e "\033[33m\t\tAuto login already configured for user: $current_autologin, skipping...\033[m"
    else
        echo -e "\033[34m\t\tSetting up Auto Login for root...\033[m"
        sed -i 's/DISPLAYMANAGER_AUTOLOGIN=\"\"/DISPLAYMANAGER_AUTOLOGIN=\"root\"/' /etc/sysconfig/displaymanager
        sed -i 's/DISPLAYMANAGER_PASSWORD_LESS_LOGIN=\"no\"/DISPLAYMANAGER_PASSWORD_LESS_LOGIN=\"yes\"/' /etc/sysconfig/displaymanager
    fi

elif [[ "$osname" =~ "Ubuntu" ]]; then
    # Ubuntu 系統配置
    OSN="Ubuntu$osversion"
    echo -e "\033[34m\t\tUbuntu System Detected: $OSN\033[m"

    # 自动检测普通用户
    USERNAME=$(getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" {print $1; exit}')
    
    if [ -z "$USERNAME" ]; then
        echo -e "\033[31m\t\tNo normal user found. Please create a user first.\033[m"
        exit 1
    fi

    # 檢查是否已設置 autologin
    if grep -q "AutomaticLoginEnable=true" /etc/gdm3/custom.conf 2>/dev/null; then
        current_user=$(grep "AutomaticLogin=" /etc/gdm3/custom.conf 2>/dev/null | cut -d'=' -f2)
        echo -e "\033[33m\t\tAuto login already configured for user: $current_user, skipping...\033[m"
    else
        echo -e "\033[34m\t\tSetting up Auto Login for $USERNAME...\033[m"
        sed -i '/\[daemon\]/d' /etc/gdm3/custom.conf
        cat << EOF >> /etc/gdm3/custom.conf
[daemon]
AutomaticLoginEnable=true
AutomaticLogin=$USERNAME
EOF
    fi

    echo -e "\033[34m\t\tDisabling Screen Lock and Screensaver...\033[m"
    gsettings set org.gnome.desktop.screensaver lock-enabled false
    gsettings set org.gnome.desktop.session idle-delay 0
fi
