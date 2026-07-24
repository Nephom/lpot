# FIXLIST — main.go 問題與修正方案（審視版）

> 建立日期: 2026-04-21
> 審視日期: 2026-04-21
>
> 審視原則：只保留「會影響程式穩定運行 / Linux 系統穩定運行」的項目。
> 純為未來防禦、風格整潔、微量記憶體最佳化等項目，均不納入本次修正。

---

## 審視總覽

| 編號 | 原建議                            | 審視結論                                                           | 本次處置                                 |
| ---- | --------------------------------- | ------------------------------------------------------------------ | ---------------------------------------- |
| 1    | 全域 map 無 mutex                 | 目前 main goroutine 嚴格順序寫入，**無實際競態**；加鎖屬未來防禦   | **不修**，改以註解記錄假設               |
| 2    | `fileExists` TOCTOU               | 威脅模型誤置；真正會跟隨 symlink 的是「寫入路徑」不是 `fileExists` | **改寫**為硬化寫入點（見下方「修正 A」） |
| 3    | 重啟前 `time.Sleep` 無法中斷      | Ctrl-C 後最長等 300 秒才退出，屬實際穩定性/可用性問題              | **修正**（見下方「修正 B」）             |
| 4    | 第二個 SIGINT 被丟棄              | 分析有誤；cap=2 channel + 已消費首訊號後不會再丟                   | **不修**                                 |
| 5    | `processPCIDevices` 重複開 log fd | `defer` 正常關閉，無 fd 洩漏，屬風格問題                           | **不修**                                 |
| 6    | log 全載入記憶體                  | 以實際每 cycle 寫入量估算，萬次 cycle 亦僅數 MB                    | **不修**                                 |
| 7    | `rootCancel` nil 檢查多餘         | 死碼但無害                                                         | **不修**                                 |

---

## 修正 A：硬化會跟隨 symlink 的寫入點（取代原 #2）

**重新定義問題**：
原建議將 `fileExists` 改用 `Lstat` 並不能解決問題——即使 `fileExists` 回傳 `false`，隨後的 `os.Create` / `os.WriteFile` 仍會跟隨 symlink。而且 `LPOT_DIR` 已由 `secureLpotDir()` 強制為 0700 且 root 擁有，非 root 使用者無法在其中植入 symlink，真實攻擊面很小。

但程式仍有少數寫入點完全沒有 `O_NOFOLLOW` 保護，若系統管理員誤操作或 supply-chain 異常造成 symlink，寫入可能被重導。這些寫入點採用 `openSecureCreateExcl` 或以 `O_TRUNC|O_NOFOLLOW` 開啟才是正確的硬化方式。

**受影響位置**（全部為寫入端，非 `fileExists` 端）：

| 位置                         | 目前寫法                                       | 風險                      |
| ---------------------------- | ---------------------------------------------- | ------------------------- |
| `writeTimestamp` (line 460)  | `os.Create(TIMESTAMP_FILE)`                    | `/lpot` 下 symlink 重導   |
| `disableSELinux` (line 701)  | `os.WriteFile("/etc/selinux/config", …, 0644)` | `/etc` 下 symlink 重導    |
| 初始 lspci dump (line 985)   | `os.WriteFile(INITIAL_PCI_DEVICES, …, 0644)`   | 同上                      |
| `executeLspci` (line 592)    | `os.WriteFile(filename, …, 0644)`              | `TMP_DIR` 下 symlink 重導 |
| `savePCIConfig` (line 1599)  | `os.WriteFile(outputFile, …, 0644)`            | 呼叫者傳入 `/lpot/*.bin`  |
| `saveIgnoreBits` (line 1687) | `os.WriteFile(filePath, …, 0644)`              | `/lpot/ignore_bits.txt`   |

**修正方案**：

1. 新增 helper `writeFileNoFollow(path string, data []byte, perm os.FileMode) error`：
   ```
   os.OpenFile(path, O_WRONLY|O_CREATE|O_TRUNC|syscall.O_NOFOLLOW, perm)
   ```
2. 將上表六處 `os.WriteFile` / `os.Create` 全部改用此 helper。
3. `fileExists` **不動**——它目前的語意（「路徑可被 stat」）是正確的，改成排除 symlink 反而會破壞那些 symlink 為合法設定的情境。
4. `disableSELinux` 若偵測到 `/etc/selinux/config` 為 symlink（`Lstat`），應拒絕改寫並警告；這屬於系統檔案，有額外謹慎的必要。

**為何需要**：`/etc/selinux/config` 被誤改為 symlink 並被本程式覆寫，可能導致下次重開機後 SELinux policy 狀態錯亂，影響 Linux 系統穩定運行（而非僅本程式）。其餘 `/lpot` 下項目屬防禦性，但既然統一了 helper，一併改成本低。

---

## 修正 B：重啟前 `time.Sleep` 無法中斷（原 #3 保留並精確化）

**位置**：`main.go` line 1034

```go
time.Sleep(time.Duration(*waitSeconds) * time.Second)
```

**問題**：

- `waitSeconds` 預設 300、上限 3600。
- 使用者在此期間按 Ctrl-C：`setupSignalHandlers` goroutine 會 `stopFlag.Store(true)` 並 `rootCancel()`，但此 `time.Sleep` 不監聽任何 channel，**必須等滿整段時間**才回到下一行。
- 下一行（line 1049）是 `runExternal(rebootCmdTimeout, rebootPath)`，因為 `rootCtx` 已被 cancel，`runExternal` 會「立刻」以 context canceled 失敗——但使用者已經在 CLI 前等了最多 1 小時。
- 更糟的情況：若使用者按了 Ctrl-C 但 sleep 結束後程式仍走到 reboot 分支（`debugMode == false`），**會真的 reboot 一台使用者已要求停止的機器**。這是實際的穩定性/可用性問題。

**修正方案**（兩步）：

1. 將 sleep 改為可中斷：
   ```go
   select {
   case <-time.After(time.Duration(*waitSeconds) * time.Second):
   case <-rootCtx.Done():
   }
   ```
2. 在執行 reboot 前加一次 `stopFlag.Load()` 檢查；為 true 則直接 return，不呼叫 reboot：
   ```go
   if stopFlag.Load() {
       fmt.Fprintf(logFp, "%s Stop requested before reboot; skipping reboot.\n", getCurrentTimestamp())
       return
   }
   ```
3. 同時更新 line 1028 前後的 log 順序不變，確保 cycle-end banner 已寫入。

**為何需要**：避免「使用者已撤回操作但機器仍被重開機」的真實風險。這會影響其他無辜工作負載。

---

## 修正 C（可選，低優先）：記錄 stats map 的單 goroutine 假設

**位置**：line 93-94 的全域宣告處。

雖然不加鎖是合理的，但為避免未來有人在 `compareAndLogDeviceChanges` / `compareDevices` 之外新增 goroutine 呼叫路徑導致 data race，建議在宣告上方加一行註解：

```go
// deviceChangeStats / configChangeStats are written only from the main
// goroutine's sequential processPCIDevices → compareDevices /
// collectStableConfig → compareAndLogDeviceChanges flow, and read only by
// generateFinalSummary after that flow completes. If any of these callers is
// ever moved to its own goroutine, a mutex must be introduced.
```

不涉及行為修改，僅為人類讀者與未來 reviewer 的提示。

---

## 未採納項目說明

### 原 #4：第二個 SIGINT 可能被丟棄

`signal.Notify` 只在 channel 滿時才丟棄訊號。本程式 channel cap 為 2：

1. 第一個 SIGINT 進入 buffer（占用 1/2）。
2. goroutine 的第一個 `<-c` 讀走，buffer 歸零。
3. 第二個 SIGINT 再來，進入 buffer（占用 1/2，可容納到 2/2）。
4. 第二個 `<-c` 讀走，`os.Exit(130)`。

要丟失訊號需在步驟 2 的 `<-c` 尚未執行前，收到 **3 個以上** SIGINT——人類 Ctrl-C 速度無此可能。且若真丟失，第三次 Ctrl-C 仍會被接收。本項不影響穩定性，不修。

### 原 #5：重複開啟 log file

`processPCIDevices` 內部 line 1187 的 `os.OpenFile` 有 `defer logFile.Close()` 成對關閉，無 fd 洩漏。每 cycle 只執行一次，成本可忽略。屬風格整潔層次，不修。

### 原 #6：log 全載入記憶體

每個 cycle 在 reboot.log 僅寫入數行（數百 bytes），LPOTSCAN_LOG 每 cycle 開頭 `os.Remove`。即使 10000 cycles 也僅約 5 MB，遠低於會造成問題的規模。不修。

### 原 #7：`rootCancel` nil 檢查

main 順序保證該指標非 nil，檢查是死碼但無害（無額外分支成本、無誤導風險）。不修。

---

# 測試規劃

下列測試針對「修正 A」「修正 B」；修正 C 為純註解改動無需測試。
建議新增於 `main_test.go`（目前專案尚無測試檔，需一併建立 `go test` 目標）。

## T-A：硬化寫入（`writeFileNoFollow` helper）

1. **T-A-1 正常建立**
   - 前置：`/tmp/lpot-test-XXXX/` 不存在 `a.txt`。
   - 呼叫 `writeFileNoFollow("…/a.txt", []byte("hello"), 0600)`。
   - 期望：回傳 nil；檔案存在、mode=0600、內容符合。

2. **T-A-2 覆寫既有一般檔案**
   - 前置：`a.txt` 已存在並含 "old"。
   - 呼叫寫入 "new"。
   - 期望：成功；內容為 "new"、長度正確（驗證 `O_TRUNC` 生效）。

3. **T-A-3 拒絕跟隨 symlink（關鍵）**
   - 前置：建立 `target.txt`（空），以及 `link.txt` → `target.txt` 的 symlink。
   - 呼叫 `writeFileNoFollow("…/link.txt", …)`。
   - 期望：回傳錯誤（`errors.Is(err, syscall.ELOOP)`）；`target.txt` 內容 **不得** 被更動。

4. **T-A-4 `disableSELinux` 面對 symlink 時拒寫**
   - 以 temp root 模擬：`/tmp/etc/selinux/config` 為 symlink → `/tmp/etc/shadow`。
   - 建構可讓 `disableSELinux` 走該 temp path 的測試變體（將路徑改為可注入變數，或以 `t.Setenv` + 介面抽換）。
   - 期望：`disableSELinux` 不覆寫 symlink 目標，並於 stderr/log 輸出警告。

5. **T-A-5 六個寫入點的 call-site 驗證**
   - 以 `grep` 或 go/analysis 靜態檢查，確認 `os.WriteFile` / `os.Create` 於 `main.go` 中不再出現於 A 節列表位置（CI 可掛 `go vet` 自訂規則或 shell test）。

## T-B：可中斷的重啟前等待

1. **T-B-1 正常等待完成**
   - 注入 `waitSeconds=1`、`debugMode=true`（避免真 reboot），執行流程。
   - 期望：約 1 秒後執行到 debug 分支並正常返回。

2. **T-B-2 Ctrl-C 中斷等待**（關鍵）
   - 啟動 `go test` 子程序跑長流程 `-s 60`，在 2 秒後對子程序送 `SIGINT`。
   - 期望：子程序在 **<=3 秒內** 結束（原行為會等 60 秒），exit code 不為 reboot 觸發；stdout/log 顯示 "Stop requested before reboot; skipping reboot."
   - 實作上建議把等待邏輯抽為 `waitForReboot(ctx context.Context, d time.Duration)`，測試直接呼叫並用 `context.WithCancel` 觸發。

3. **T-B-3 stopFlag 攔截 reboot**
   - 預先 `stopFlag.Store(true)` 再呼叫重構後的等待+reboot 包裝函式。
   - 期望：`rebootPath` 不被執行。可藉由注入假的 `runExternal` mock 計數器驗證。

4. **T-B-4 `debugMode` 流程不受影響**
   - 同 T-B-1 但 waitSeconds=5 且不送訊號。
   - 期望：5 秒後輸出 `DEBUG: Reboot command disabled in debug mode`，無 reboot 被呼叫。

## 執行方式

```
cd /Users/ascopia/Project/lpot/lpot_integrated
go test ./... -run 'TestWriteFileNoFollow|TestDisableSELinux|TestWaitForReboot' -v
```

由於現行程式大量使用全域變數與絕對路徑常數，執行 T-A-4 / T-B-2 前需先做最小幅度重構（將 `/etc/selinux/config`、等待+reboot 段落抽成可注入的函式），以避免在測試中觸發真實 reboot 或寫入系統目錄。此重構會在實作修正 A、B 時一併完成。
