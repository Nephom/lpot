#region === 參數設置 ===
param (
    [int]$t = 12,           # 運行時間，單位：小時，預設 12 小時
    [int]$d = 300,          # 每次執行之間的延遲時間，單位：秒，預設 300 秒
    [switch]$stopForce,     # 修正拼寫錯誤：stopFroce -> stopForce
    [switch]$verbose        # 新增詳細輸出選項
)

# 常量設置
$outputFilePath = "C:\PCI_Device_Info.csv"
$logFilePath = "C:\reboot.log"
$rebootCountFile = "C:\rebootcount"
$timestampFile = "C:\timestamp"
$taskName = "lpot"
$autoLoginUser = "Administrator"
$autoLoginPassword = "password,1"
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# 顏色配置
$Colors = @{
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'Cyan'
    Header = 'Magenta'
    Separator = 'DarkGray'
}
#endregion

#region === 輸出格式化函數 ===
function Write-ColoredOutput {
    param(
        [string]$Message,
        [string]$Color = 'White',
        [switch]$NoNewline
    )

    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-Header {
    param([string]$Title)

    $separator = "=" * 60
    Write-ColoredOutput $separator -Color $Colors.Separator
    Write-ColoredOutput " $Title " -Color $Colors.Header
    Write-ColoredOutput $separator -Color $Colors.Separator
}

function Write-SubHeader {
    param([string]$Title)

    $separator = "-" * 40
    Write-ColoredOutput $separator -Color $Colors.Separator
    Write-ColoredOutput $Title -Color $Colors.Info
    Write-ColoredOutput $separator -Color $Colors.Separator
}

function Write-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet('Success', 'Warning', 'Error', 'Info')]
        [string]$Status = 'Info'
    )

    $prefix = switch ($Status) {
        'Success' { "[✓]" }
        'Warning' { "[!]" }
        'Error'   { "[✗]" }
        'Info'    { "[i]" }
    }

    Write-ColoredOutput "$prefix " -Color $Colors.$Status -NoNewline
    Write-ColoredOutput $Message
}
#endregion

#region === Log Handling ===
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp | [$Level] | $Message"

    # 寫入日誌文件
    Add-Content -Path $logFilePath -Value $logEntry

    # 如果啟用詳細模式，同時輸出到控制台
    if ($verbose) {
        Write-StatusMessage $Message -Status $Level
    }
}
#endregion

#region === 自動登入設置 ===
function Set-AutoLogin {
    Write-StatusMessage "檢查自動登入設置..." -Status Info

    try {
        $currentAutoLogon = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue

        if ($currentAutoLogon.AutoAdminLogon -eq "1" -and `
            $currentAutoLogon.DefaultUsername -eq $autoLoginUser -and `
            $currentAutoLogon.DefaultPassword -eq $autoLoginPassword) {

            Write-StatusMessage "自動登入已正確設置" -Status Success
            Write-Log "Auto-login is already configured correctly" -Level Success
        }
        else {
            Write-StatusMessage "設置自動登入..." -Status Warning
            Set-ItemProperty -Path $registryPath -Name "AutoAdminLogon" -Value "1"
            Set-ItemProperty -Path $registryPath -Name "DefaultUsername" -Value $autoLoginUser
            Set-ItemProperty -Path $registryPath -Name "DefaultPassword" -Value $autoLoginPassword
            Write-StatusMessage "自動登入設置完成" -Status Success
            Write-Log "Auto-login configured successfully" -Level Success
        }
    }
    catch {
        Write-StatusMessage "設置自動登入時發生錯誤: $($_.Exception.Message)" -Status Error
        Write-Log "Failed to configure auto-login: $($_.Exception.Message)" -Level Error
        throw
    }
}
#endregion

#region === Task 設定 ===
function Ensure-TaskExists {
    Write-StatusMessage "檢查排程任務..." -Status Info

    try {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

        if (-not $existingTask) {
            Write-StatusMessage "建立排程任務..." -Status Warning

            # 取得當前執行檔的路徑
            $currentExePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

            # 建立排程任務，並執行當前執行檔
            $action = New-ScheduledTaskAction -Execute $currentExePath -Argument "-t $t -d $d"
            $trigger = New-ScheduledTaskTrigger -AtStartup
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User "$autoLoginUser" -Password "$autoLoginPassword" -RunLevel Highest

            Write-StatusMessage "排程任務建立完成" -Status Success
            Write-Log "Scheduled task '$taskName' created successfully" -Level Success
        } else {
            Write-StatusMessage "排程任務已存在" -Status Success
            Write-Log "Scheduled task '$taskName' already exists" -Level Info
        }
    }
    catch {
        Write-StatusMessage "建立排程任務時發生錯誤: $($_.Exception.Message)" -Status Error
        Write-Log "Failed to create scheduled task: $($_.Exception.Message)" -Level Error
        throw
    }
}
#endregion

#region === Reboot Count & Timestamp ===
function Update-RebootCount {
    try {
        if (-not (Test-Path $rebootCountFile)) {
            Set-Content -Path $rebootCountFile -Value 0
            Write-StatusMessage "建立重啟計數文件" -Status Info
        }

        $count = [int](Get-Content -Path $rebootCountFile) + 1
        Set-Content -Path $rebootCountFile -Value $count

        Write-StatusMessage "重啟次數: $count" -Status Info
        Write-Log "Reboot count updated to: $count" -Level Info

        return $count
    }
    catch {
        Write-StatusMessage "更新重啟計數時發生錯誤: $($_.Exception.Message)" -Status Error
        Write-Log "Failed to update reboot count: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-OrCreateTimestamp {
    try {
        if (-not (Test-Path $timestampFile)) {
            $endTime = (Get-Date).AddHours($t)
            $endTime | Set-Content -Path $timestampFile
            Write-StatusMessage "設定結束時間: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Status Info
            Write-Log "Record endTime: $endTime" -Level Info
        }

        $endTime = [DateTime](Get-Content -Path $timestampFile)
        $remainingTime = $endTime - (Get-Date)

        if ($remainingTime.TotalMinutes -gt 0) {
            Write-StatusMessage "剩餘測試時間: $([math]::Round($remainingTime.TotalHours, 2)) 小時" -Status Info
        } else {
            Write-StatusMessage "測試時間已到期" -Status Warning
        }

        return $endTime
    }
    catch {
        Write-StatusMessage "處理時間戳記時發生錯誤: $($_.Exception.Message)" -Status Error
        Write-Log "Failed to process timestamp: $($_.Exception.Message)" -Level Error
        throw
    }
}
#endregion

#region === PCI Device Scan Function ===
function Get-PCIDeviceProperties {
    Write-StatusMessage "掃描 PCI 設備..." -Status Info
    Write-Log "Scanning PCI devices..." -Level Info

    $pciDevices = @()
    $deviceCount = 0

    try {
        Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI" | ForEach-Object {
            $deviceRoot = $_.PSPath
            $deviceID = $_.PSChildName

            Get-ChildItem $deviceRoot -ErrorAction SilentlyContinue | ForEach-Object {
                $subFolderPath = $_.PSPath
                $instanceId = "PCI\$deviceID\$($_.PSChildName)"
                $hasControl = Test-Path "$subFolderPath\Control"
                $deviceCount++

                $propertiesDetails = @{}
                try {
                    $deviceProperties = Get-PnpDeviceProperty -InstanceId $instanceId -ErrorAction Stop
                    foreach ($prop in $deviceProperties) {
                        if ($prop.KeyName -like "DEVPKEY*" -and
                            $prop.KeyName -notlike "*Date*") {
                            $propertiesDetails[$prop.KeyName] = $prop.Data
                        }
                    }
                } catch {
                    Write-Log "Failed to fetch properties for InstanceId: $instanceId | Error: $_" -Level Warning
                }

                $pciDevices += [PSCustomObject]@{
                    DeviceID = $deviceID
                    SubFolder = $_.PSChildName
                    InstanceId = $instanceId
                    HasControl = $hasControl
                    PropertiesDetails = $propertiesDetails
                }
            }
        }

        Write-StatusMessage "找到 $deviceCount 個 PCI 設備" -Status Success
        Write-Log "Found $deviceCount PCI devices" -Level Success

        return $pciDevices
    }
    catch {
        Write-StatusMessage "掃描 PCI 設備時發生錯誤: $($_.Exception.Message)" -Status Error
        Write-Log "Failed to scan PCI devices: $($_.Exception.Message)" -Level Error
        throw
    }
}
#endregion

#region === PCI 比對與記錄差異 ===
function Compare-PCIInfo {
    param ($existingPciInfo, $currentPciInfo)

    Write-StatusMessage "比對 PCI 設備變化..." -Status Info
    Write-Log "Comparing PCI device changes..." -Level Info

    $differences = @()
    $changeCount = @{
        Added = 0
        Removed = 0
        PropertyChanged = 0
        PropertyAdded = 0
        PropertyRemoved = 0
    }

    try {
        # 檢查新增和移除的設備
        foreach ($currentDevice in $currentPciInfo) {
            $match = $existingPciInfo | Where-Object {
                $_.DeviceID -eq $currentDevice.DeviceID -and
                $_.SubFolder -eq $currentDevice.SubFolder
            }

            $deviceName = $currentDevice.PropertiesDetails['DEVPKEY_NAME']
            if (-not $deviceName) { $deviceName = "Unknown Device ($($currentDevice.DeviceID))" }

            # 如果從 False 變成 True，視為 Added Device
            if ($match -and $match.HasControl -eq $false -and $currentDevice.HasControl -eq $true) {
                $differences += "Added Device: $deviceName"
                $changeCount.Added++
                continue
            }

            # 如果從 True 變成 False，視為 Removed Device
            if ($match -and $match.HasControl -eq $true -and $currentDevice.HasControl -eq $false) {
                $differences += "Removed Device: $deviceName"
                $changeCount.Removed++
                continue
            }

            # 只有在 HasControl 相等的情況下才比較其他屬性
            if ($match -and $match.HasControl -eq $currentDevice.HasControl) {
                # 比較特定屬性的變化
                foreach ($key in $currentDevice.PropertiesDetails.Keys) {
                    # 檢查這個 Key 是否在舊的記錄中存在
                    if ($match.PropertiesDetails.ContainsKey($key)) {
                        # 比較值是否有變化
                        if ($match.PropertiesDetails[$key] -ne $currentDevice.PropertiesDetails[$key]) {
                            $differences += "Property Changed: $deviceName | $key | From '$($match.PropertiesDetails[$key])' to '$($currentDevice.PropertiesDetails[$key])'"
                            $changeCount.PropertyChanged++
                        }
                    }
                    else {
                        # 如果是新出現的 Key
                        $differences += "New Property Added: $deviceName | $key | Value: '$($currentDevice.PropertiesDetails[$key])'"
                        $changeCount.PropertyAdded++
                    }
                }
                # 檢查是否有屬性被移除
                foreach ($key in $match.PropertiesDetails.Keys) {
                    if (-not $currentDevice.PropertiesDetails.ContainsKey($key)) {
                        $differences += "Property Removed: $deviceName | $key | Previous Value: '$($match.PropertiesDetails[$key])'"
                        $changeCount.PropertyRemoved++
                    }
                }
            }
        }

        # 顯示變化統計
        $totalChanges = $changeCount.Values | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        if ($totalChanges -gt 0) {
            Write-SubHeader "變化統計"
            Write-ColoredOutput "  新增設備: $($changeCount.Added)" -Color $Colors.Success
            Write-ColoredOutput "  移除設備: $($changeCount.Removed)" -Color $Colors.Error
            Write-ColoredOutput "  屬性變更: $($changeCount.PropertyChanged)" -Color $Colors.Warning
            Write-ColoredOutput "  新增屬性: $($changeCount.PropertyAdded)" -Color $Colors.Info
            Write-ColoredOutput "  移除屬性: $($changeCount.PropertyRemoved)" -Color $Colors.Warning
            Write-ColoredOutput "  總計變化: $totalChanges" -Color $Colors.Header
        }

        return $differences
    }
    catch {
        Write-StatusMessage "比對 PCI 設備時發生錯誤: $($_.Exception.Message)" -Status Error
        Write-Log "Failed to compare PCI devices: $($_.Exception.Message)" -Level Error
        throw
    }
}
#endregion

#region === Main Script Logic ===
# 顯示腳本標題
Write-Header "PCI 設備長期監控測試 (LPOT)"

Write-StatusMessage "檢查系統中的錯誤設備..." -Status Info
$errorDevices = Get-PnpDevice -PresentOnly | Where-Object { $_.Status -eq 'Error' }

if ($errorDevices) {
    Write-SubHeader "發現錯誤設備"
    foreach ($device in $errorDevices) {
        Write-ColoredOutput "  ✗ $($device.FriendlyName) - $($device.Status)" -Color $Colors.Error
    }
    Write-StatusMessage "發現 PCI 設備狀態異常，可能未安裝驅動程式" -Status Error
    Write-Log "Found PCI devices with error status, might be missing drivers" -Level Error
    exit 1  # 使用非零的退出代碼表示發生錯誤
} else {
    Write-StatusMessage "所有設備狀態正常" -Status Success
}

Write-SubHeader "系統初始化"
Set-AutoLogin
Ensure-TaskExists

$endTime = Get-OrCreateTimestamp
$rebootCount = Update-RebootCount

Write-Header "開始測試循環"
Write-Log "############# Start LPOT Test #############" -Level Info
Write-Log "Reboot Count: $rebootCount" -Level Info
Write-Log "Test will end at: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Info

# 檢查輸出文件是否存在
if (Test-Path $outputFilePath) {
    Write-SubHeader "載入先前的 PCI 設備資訊"
    Write-StatusMessage "從檔案載入先前的設備資訊..." -Status Info

    try {
        # 確保匯入的 CSV 能正確轉換
        $existingPciInfo = Import-Csv -Path $outputFilePath | ForEach-Object {
            # 重建 PropertiesDetails 作為雜湊表
            $propertiesDict = @{}
            if ($_.PropertiesDetails) {
                $_.PropertiesDetails -split "; " | ForEach-Object {
                    $parts = $_ -split ": ", 2  # 限制分割為2部分，避免值中包含冒號的問題
                    if ($parts.Count -eq 2) {
                        $propertiesDict[$parts[0]] = $parts[1]
                    }
                }
            }

            [PSCustomObject]@{
                DeviceID = $_.DeviceID
                SubFolder = $_.SubFolder
                InstanceId = $_.InstanceId
                HasControl = ($_.HasControl -eq "True")  # 顯式轉換為布林值
                PropertiesDetails = $propertiesDict
            }
        }

        Write-StatusMessage "載入了 $($existingPciInfo.Count) 個先前的設備記錄" -Status Success

        $pciDeviceInfo = Get-PCIDeviceProperties

        # 比對 PCI 資訊
        $differences = Compare-PCIInfo -existingPciInfo $existingPciInfo -currentPciInfo $pciDeviceInfo

        if ($differences.Count -gt 0) {
            Write-SubHeader "發現設備變化"
            foreach ($diff in $differences) {
                Write-ColoredOutput "  $diff" -Color $Colors.Warning
                Write-Log $diff -Level Warning
            }

            if ($stopForce.IsPresent) {
                Write-StatusMessage "偵測到錯誤，強制停止執行" -Status Error
                Write-Log "Detect Error occurred! EXIT" -Level Error
                exit
            }
        } else {
            Write-StatusMessage "未偵測到設備變化" -Status Success
            Write-Log "No changes detected." -Level Success
        }

        # 更新 CSV 檔案
        Write-StatusMessage "更新設備資訊檔案..." -Status Info
        $exportData = $pciDeviceInfo | ForEach-Object {
            $propertiesString = ($_.PropertiesDetails.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "; "
            [PSCustomObject]@{
                DeviceID = $_.DeviceID
                SubFolder = $_.SubFolder
                InstanceId = $_.InstanceId
                HasControl = $_.HasControl
                PropertiesDetails = $propertiesString
            }
        }
        $exportData | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding UTF8
        Write-StatusMessage "設備資訊檔案已更新" -Status Success

    } catch {
        Write-StatusMessage "處理設備資訊時發生錯誤: $($_.Exception.Message)" -Status Error
        Write-Log "Failed to process device information: $($_.Exception.Message)" -Level Error
        throw
    }

} else {
    Write-SubHeader "首次執行 - 建立基準設備資訊"
    Write-StatusMessage "首次執行，建立基準設備資訊..." -Status Info

    $pciDeviceInfo = Get-PCIDeviceProperties

    # 將 PropertiesDetails 轉換回字串以便儲存
    $exportData = $pciDeviceInfo | ForEach-Object {
        $propertiesString = ($_.PropertiesDetails.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "; "
        [PSCustomObject]@{
            DeviceID = $_.DeviceID
            SubFolder = $_.SubFolder
            InstanceId = $_.InstanceId
            HasControl = $_.HasControl
            PropertiesDetails = $propertiesString
        }
    }

    $exportData | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding UTF8
    Write-StatusMessage "基準設備資訊已儲存到 $outputFilePath" -Status Success
    Write-Log "Baseline PCI device information saved to $outputFilePath" -Level Success
}

Write-SubHeader "準備重新啟動"
Write-StatusMessage "等待 $d 秒後重新啟動系統..." -Status Info
Write-Log "Waiting $d seconds before rebooting..." -Level Info

# 顯示倒數計時
for ($i = $d; $i -gt 0; $i--) {
    if ($i % 60 -eq 0 -or $i -le 10) {
        Write-ColoredOutput "重新啟動倒數: $i 秒" -Color $Colors.Warning
    }
    Start-Sleep -Seconds 1
}

Write-StatusMessage "正在重新啟動系統..." -Status Warning
Write-Log "Rebooting system." -Level Info
Restart-Computer -Force
#endregion