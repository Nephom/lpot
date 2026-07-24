# 未完成 / 待追蹤工作清單

本檔列出本輪修改中「尚未動工」或「動工後刻意撤回」的項目，作為下一輪
維護的起點。對應的程式碼變更（短 BDF 統一、三層 endpoint 過濾、
`pcie_filter.txt` 覆寫、`-classify` 旗標、reboot-fixed 80 % 門檻、
`Filtered Devices` 區段）已全部進入 `main.go`，`go build` / `go vet` /
`go test`（既有測試）皆通過。

---

## 1. 單元測試 (高優先 — 使用者明示暫不執行)

我曾試寫以下測試，因有兩個案例需要進一步調整、且使用者裁示「不用測試了」
而全部撤回。下次補測試時建議從這些開始：

- `TestNormalizeBDF`
  - 注意：`normalizeBDF` 只剝離 `0000:` 這個正規 Linux domain；
    非 `0000:` 的多 domain 形式（例：`0001:ef:00.0`）應**原樣保留**，
    測試案例需據此修正。
- `TestHasPCIeCapability`
  - 用一塊 256 byte 合成 buffer，分別驗證
    (a) cap chain 含 ID 0x10、(b) chain 只含其他 ID、(c) Status 第 4 bit
    未設三種情境。
- `TestIsPCIeEndpoint`
  - 純函式測試，覆蓋 Header Type≠0 / BaseClass==0x06 /
    `HasPCIeCap==false` 三條 reject 規則與正常 endpoint。
- `TestLoadPCIeFilterOverrides` / `..._Missing`
  - 驗證 `+`、`-`、裸 BDF（視為 include）、`#` 註解、空行、缺檔
    （非錯誤、回空集合）等行為。
- `TestSplitDevices_NormalizesBDF`
  - 注意：`splitDevices` 用 `\n# ` 切段，**第一個** device header
    不會被切走（pre-existing quirk，見第 3 節）。測試 body 必須在第一
    個 `# ` 前面加 `\n`，或以兩個以上裝置構造輸入。

> 既有測試（`writeFileNoFollow` / SELinux / `sleepInterruptible`）未受影響。

---

## 2. `pcie_filter.txt` 使用者文件

- 目前格式只在 `showHelp()` 一行帶過、以及程式註解中描述，沒有獨立
  說明檔。下一輪建議在 `README` 或 `docs/` 增加：
  - 檔案路徑：`/lpot/pcie_filter.txt`
  - 語法：`+ BDF`（強制納入）、`- BDF`（強制排除）、裸 `BDF`（視為
    include）、`#` 註解、空行忽略
  - BDF 形式：短碼 (`21:00.4`) 或長碼 (`0000:21:00.4`) 皆可，內部會
    正規化成短碼
  - `-` 永遠優先於 `+`（Exclude beats Include）
  - 範例：搭配 `-classify` 先 dry-run 看分類結果，再決定要不要加例外

---

## 3. 已知 pre-existing quirk（非本輪引入，但建議排程修）

`splitDevices()` (`main.go`) 用 `bytes.Split(data, []byte("\n# "))` 切
段，因此檔案的**第一個** device header（緊接檔頭那一個）不會被切割，
其 `busID` 會被解析成 `"# 0000:xx:xx.x"`（含 `# ` 前綴），導致該裝置在
比對時實質上被「漏掉」。

- 影響：`initial.bin` 第一個裝置在 `compareDeviceConfigs` 永遠不會比中
  ；目前累積流量中沒有報過問題，可能是因為第一個裝置通常是 host
  bridge，本來就會被新加的 endpoint filter 濾掉。
- 修法建議：在 `splitDevices` 開頭先做 `data = append([]byte("\n"), data...)`
  或改用 `Scanner` 逐行解析。
- 因屬既有行為、修改面較大，本輪刻意不動。

---

## 4. 摘要區段可進一步抽 helper（低優先）

`generateConfigSpaceSummary` 內 80 % 門檻分桶與表格輸出的邏輯目前是
inline 寫在函式裡。若日後要在其他報表（例如 lpotscan 摘要）共用相同
分桶規則，建議抽出：

- `func partitionByRebootFixed(deviceChanges map[string]map[string]int, totalCycles int, threshold float64) (fixed, volatile []row)`
- `func writeChangeTable(w io.Writer, title string, rows []row)`

抽出後也方便為 80 % 門檻寫單元測試。

---

## 5. `endpointFilterSet` 的可觀測性

目前 `endpointFilterSet` 只在 `main()` 啟動時建立一次；之後若有熱插拔
裝置（cycle 中途出現的新 BDF），會落入「未在 set 內」而被當作非
endpoint 略過。

- 影響：對標準 reboot 測試無影響（每次 reboot 後 process 重啟，set
  會重建）；但若日後改為長駐 daemon、跨 reboot 不重啟，需要在
  topology change 偵測點同步擴充 set。
- 修法建議：在 `processPCIDevices` 偵測到 `NEW Device` 時，對該 BDF 再
  跑一次 `classifyDevices` 並合併進 set；同步寫入 skipped 紀錄。

---

## 6. 文件待補（純文件，使用者未明示要寫）

- `README` 需補充：
  - 新的 `-classify` 旗標用途
  - `pcie_filter.txt` 規格（見第 2 節）
  - 摘要報表新欄位：`Reboot-fixed offsets` vs `Volatile offsets` 的
    判斷準則（≥ 80 % cycles）
  - `Filtered Devices` 區段如何閱讀

> 依使用者要求，未主動建立任何 `*.md`/`README` 變更；列入清單供下次確認。

---

## 7. 風險檢查清單（請於下一次實機驗證時對照）

- [ ] 在實際 Linux 系統上跑 `sudo ./lpot_integrated -classify`，確認
      輸出表格中 NVMe SSD / GPU / NIC 等 user-installed endpoint 皆為
      `KEEP endpoint`，AMD/Intel root port、PCI bridge 皆為
      `SKIP Header Type 1 (bridge layout)` 或 `Base Class 0x06`。
- [ ] 連續兩次 `-scan` 產生的 `ignore_bits.txt` 內容相同，且 BDF 皆為
      短碼。
- [ ] 跑一輪 ≥ 5 cycles 的 reboot 測試，確認：
  - `reboot.log` 內 `[Cycle N] | BDF | field` 行的 BDF 是短碼且帶有
    廠商 / 裝置 ID 與 class name。
  - 結尾摘要含 `Filtered Devices` 區段，且 `Reboot-fixed offsets` /
    `Volatile offsets` 兩張表正確分桶。
- [ ] 將某顆已知 endpoint 加入 `pcie_filter.txt` 並以 `-` 排除後，
      `-classify` 與摘要均反映該裝置被使用者排除。
