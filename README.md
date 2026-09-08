# VPN Gate KR → Mihomo

自動從 VPN Gate 官方 CSV API 取得 Korea Republic of 節點，並結合官方 server table 的 UDP OpenVPN endpoint 資訊，產生可供 Clash Verge Rev / Mihomo 使用的 YAML。

## 訂閱檔

固定檔名：`vpngate_kr_mihomo.yaml`

目前固定訂閱來源：

`https://raw.githubusercontent.com/chuccb/vpngate-kr-mihomo/main/vpngate_kr_mihomo.yaml`

## 目前規則

- 以 VPN Gate 官方 CSV API：`https://www.vpngate.net/api/iphone/` 作為主要節點資料與排序來源
- 以官方 server table：`https://www.vpngate.net/en/` 只補充 UDP OpenVPN 的正式下載 endpoint
- `CountryLong = Korea Republic of` 且 `CountryShort = KR`
- 官方 Ping **< 40 ms**（嚴格小於 40，不包含 40）
- 只接受實際解析後確認為 **UDP OpenVPN** 的 profile
- **最多 10 個節點**
- 依官方 Ping 由低到高排序；Speed、Score 作次要排序
- 會持續驗證候選，直到取得最多 10 個有效 UDP profile 或候選耗盡
- 去除重複的 OpenVPN `(server, port)` endpoint
- 只保留一個 `KR-LOWEST` `url-test` 群組，不建立 `KR-SELECT`
- `KR-LOWEST` 使用 `https://www.naver.com/` 做 Mihomo health-check
- `tolerance: 0`，嚴格偏好最低測得延遲
- `lazy: true`，避免未使用群組時持續背景 health-check
- `disable-udp: false`
- `PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST`
- TUN 預設 `stack: system`

## v7.2 執行優化

v7.1 的 parser、OpenVPN profile 驗證與 Mihomo 欄位轉換仍被保留作為相容性基礎；v7.2 主要優化「怎麼取得與驗證候選」，不任意篡改 VPN Gate 的實際 VPN 加密／傳輸參數。

主要改動：

- UDP profile 驗證改為**有限度平行處理**，預設 4 workers、8 筆一批；每個 worker 使用獨立 `requests.Session`，避免跨執行緒共享 Session。
- 保持候選的官方 Ping / Speed / Score 排序；平行化只加速驗證，不改變最終排序邏輯。
- 不再要求 CSV 一定存在 `OpenVPN_ConfigData_Base64` 才進入候選；若 CSV 沒有 profile，仍可嘗試官方 server table 的 UDP endpoint。
- YAML 寫出前會再次以實際的 `ovpn_to_mihomo()` 轉換結果做最終篩選，因此 `source_candidates.json` 不會記錄一個最後根本沒被產出的節點。
- 若最終 Mihomo proxy 數低於安全下限，產生流程直接失敗，不允許拿不完整訂閱去覆蓋正式檔。

## 為什麼使用「CSV + 官方 UDP endpoint」雙來源

VPN Gate CSV API 的 `OpenVPN_ConfigData_Base64` 並不代表該 profile 一定是 UDP。實際更新中，符合 Korea + Ping < 40 ms 的候選裡曾有不少 API profile 解碼後為 TCP。

因此流程是：

1. CSV API 提供 Korea 節點、Ping、Speed、Score 與 profile metadata。
2. 先依官方 Ping / Speed / Score 排出候選。
3. 若 CSV profile 本身解碼後就是 UDP，直接使用。
4. 若 CSV profile 是 TCP、無法解析，或不存在，則從官方 server table 找同一 IP 的 UDP OpenVPN endpoint。
5. 使用 VPN Gate 官方 `openvpn_download.aspx` + `udp=1` 下載真正的 UDP `.ovpn`。
6. 再次解析、驗證並轉成 Mihomo OpenVPN 節點。

這樣可以避免把 TCP profile 誤當成 UDP，同時保留 VPN Gate 官方資料來源。

## OpenVPN profile 處理

程式不會為了「理論上比較快」而任意修改 VPN Gate profile 的傳輸參數，而是盡可能保留官方 profile 的實際設定。

目前支援並驗證：

- `username/password` 或 `cert/key` 二選一
- `ca`、client certificate、private key
- `tls-auth` + `key-direction`
- `tls-crypt`
- `tls-crypt-v2`
- `cipher`
- `data-ciphers`
- `data-ciphers-fallback`
- `auth`
- `comp-lzo`
- `ping`、`ping-restart`、`handshake-timeout`、`peer-info`

Mihomo 官方目前的 OpenVPN 文件同樣要求 `username/password` 與 `cert/key` 擇一，並支援 UDP、cipher、data-ciphers、TLS key 等欄位；因此生成器不會為了效能而憑空加入不屬於原 profile 的設定。

## Clash Verge Rev / Windows TUN

這個 repo 的目標使用端是 **Clash Verge Rev on Windows + Mihomo**，因此 TUN 設計以 Clash Verge 實際行為為準，而不是只看裸 Mihomo CLI。

產出的核心設定：

```yaml
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
```

Clash Verge Rev 官方文件說明，TUN 是透過虛擬網卡與系統路由接管流量，與系統代理不同；系統代理本身不能代理 UDP，因此 FreeStyle Reboot 這類遊戲流量需要 TUN。官方文件也指出 TUN 預設使用 GVisor，並要求在 Windows 上注意 `verge-mihomo` / `verge-mihomo-alpha` 的防火牆放行。

本 repo 刻意固定 `stack: system`，並不宣稱它在所有電腦絕對最快；這是針對 Windows 遊戲 UDP 路徑的穩定／低額外負擔取向。Clash Verge Rev 官方 issue 也顯示 system/mixed/gvisor 在不同 Windows 執行模式下存在權限與防火牆差異，因此不要只看 YAML 就認定任何機器都能用 system stack。

另外，Clash Verge Rev 的 GUI TUN 選項可能影響最後合併設定；官方專案已有 issue 記錄 GUI 的 TUN 選項會讓 profile 中明寫的 `stack` 被覆寫。因此使用本訂閱時，應以 Clash Verge Rev 顯示的「實際生效設定」為準。

## 延遲與排序的重要限制

GitHub Actions 使用的是 VPN Gate 官方 CSV 的 Ping，因此 `<40ms` 是「VPN Gate 官方 Ping」，不是台灣使用者到該 VPN 節點的實際 RTT。

節點載入到 Mihomo 後，`KR-LOWEST` 才會在你的本機網路環境中對 `https://www.naver.com/` 做 health-check，並依實測延遲選擇節點。Mihomo 的 API 也提供 proxy/group 的 delay history，實際選擇結果仍以本機測得資料為準。

HTTP health-check 也不是 FreeStyle Reboot 的遊戲 UDP RTT，因此不能把 Naver 延遲直接當成遊戲 Ping。

## 自動更新

GitHub Actions 每 6 小時重新抓取一次。生成、YAML reload 與語意驗證全部成功後才會替換正式訂閱檔。

Push workflow 已限制為 `main` 分支；因此開發分支可以跑生成／驗證而不會把測試結果直接發布到正式 `main`。

Publish 階段保留 main 分支 race retry：若 push 因遠端分支短暫前進失敗，會重新同步 `origin/main` 並最多重試 3 次。

## 驗證

正式產物會先經過 YAML reload 與語意驗證，包括：

- 節點數量 3～10
- 所有節點為 UDP OpenVPN
- server / port 合法
- authentication mode 正確
- TLS 模式互斥
- cipher / auth / compression / data-ciphers 符合 Mihomo OpenVPN 支援範圍
- PEM 多行內容沒有被 YAML 破壞
- 單一 `KR-LOWEST` 群組
- `lazy: true`、`interval: 60`、`timeout: 3000`、`tolerance: 0`
- FreeStyle Reboot process rule 存在
- candidate metadata 的來源、版本、國家與 Ping 條件正確

這是 YAML 與語意層驗證；目前仍沒有在 GitHub Actions 中啟動真實 Mihomo binary 做完整 boot/connect smoke test，因而不會把「YAML 通過」冒充成「所有節點一定可連線」。

## 安全設計

- 不提交 `.ovpn` 原始檔
- 不提交 build 中間產物
- `source_candidates.json` 只保存節點 metadata，不保存完整 profile
- 不混用 OpenVPN 的 username/password 與 cert/key 認證模式
- 只處理 VPN Gate 官方公開 profile 材料
- 生成或驗證失敗時不以失敗產物覆蓋既有訂閱
