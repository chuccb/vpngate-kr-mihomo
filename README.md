# VPN Gate KR → Mihomo

自動從 VPN Gate 官方 CSV API 取得 Korea Republic of 節點，直接解碼 API 提供的 `OpenVPN_ConfigData_Base64`，轉換成可供 Clash Verge Rev / Mihomo 使用的 YAML。

## 訂閱檔

固定檔名：`vpngate_kr_mihomo.yaml`

目前固定訂閱來源：

`https://raw.githubusercontent.com/chuccb/vpngate-kr-mihomo/main/vpngate_kr_mihomo.yaml`

## 目前規則

- 使用 VPN Gate 官方 CSV API：`https://www.vpngate.net/api/iphone/`
- 不再依賴 HTML server table scraping
- 直接使用官方 CSV 的 `OpenVPN_ConfigData_Base64`，不再逐台呼叫 `openvpn_download.aspx`
- `CountryLong = Korea Republic of` 且 `CountryShort = KR`
- 官方 Ping **< 40 ms**（嚴格小於 40，不包含 40）
- 只接受實際解析後的 **UDP OpenVPN** profile
- **最多 10 個節點**
- 先依官方 Ping 由低到高，再以 Speed、Score 作次要排序
- 不是只檢查前 10 筆：會持續掃描候選，直到取得 10 個有效、可轉換的 UDP profile 或候選耗盡
- 去除重複的 OpenVPN `(server, port)` endpoint
- 只保留一個 `KR-LOWEST` `url-test` 群組，不建立 `KR-SELECT`
- `KR-LOWEST` 使用 `https://www.naver.com/` 做 Mihomo health-check
- `tolerance: 0`，嚴格偏好最低 health-check 延遲
- `lazy: true`，群組沒有被實際使用時不持續做背景 health-check
- `disable-udp: false`
- `PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST`
- TUN 預設 `stack: system`

## 為什麼改用官方 CSV API

VPN Gate 的官方 CSV API 直接提供完整的伺服器資料與 `OpenVPN_ConfigData_Base64`。相較於解析 HTML 後再逐台拼接下載網址，直接使用 CSV API 的結構化資料更不依賴網頁版面，也少掉大量逐台 HTTP 請求。

這也讓節點選擇流程變得正確：先取得完整候選資料，再按 Ping 排序，逐個解碼並嚴格驗證 OpenVPN profile；某一個 profile 無效時，會自動跳過並繼續找下一個候選，不會因前面幾筆失敗而提早湊不滿 10 個節點。

## OpenVPN profile 處理

程式會保留官方 profile 的實際設定，而不是為了「看起來比較快」而強制改 cipher、auth、MTU 或其他傳輸參數。

支援並驗證：

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
- 官方 profile 若提供 `ping`、`ping-restart`、`handshake-timeout`、`peer-info`，則保留

VPN Gate 公開 profile 可能故意附帶共享／dummy client certificate/key。這種官方公開材料會依 profile 原樣保留；若 profile 使用 `auth-user-pass`，則使用 VPN Gate 公開的 `vpn / vpn` 認證模式，而且絕不與 cert/key 混用。

## 延遲與排序的重要限制

GitHub Actions 使用的是 VPN Gate 官方資料中的 Ping，因此 `<40ms` 是「VPN Gate 官方 Ping」，不是你的台灣電腦到該 VPN 節點的實際 RTT。

節點載入到 Mihomo 後，`KR-LOWEST` 才會使用你本機實際網路環境測試 `https://www.naver.com/`，並依 health-check 延遲選擇節點。因此產生時的 Ping 排序只是候選優先順序，真正使用時仍由 Mihomo 的本機測試結果決定。

HTTP health-check 也不是 FreeStyle Reboot 遊戲伺服器的 UDP RTT，因此不能把 Naver health-check 延遲直接當成遊戲內 Ping。

## TUN / 遊戲設定

目前產出的 TUN 是：

```yaml
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
```

`system` 沒有被當成絕對最快，而是作為這個專案的保守遊戲 UDP 預設。Mihomo 官方目前同時提供 `system`、`gvisor`、`mixed`，且文件指出多網卡環境可手動指定 outbound interface；因此若 Windows 上有多個虛擬網卡，最終生效設定應以 Clash Verge Rev 的 core configuration 為準。

## 自動更新

GitHub Actions 每 6 小時重新抓取一次，並在 workflow 驗證成功後才替換訂閱檔。

Publish 階段保留 main 分支 race retry：若 push 因遠端分支短暫前進失敗，會重新同步 `origin/main` 並最多重試 3 次。

## 驗證

產物會先經過 YAML reload 與語意驗證，包括：

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

這是 YAML 與語意層驗證；目前沒有宣稱在 GitHub Actions 中啟動真實 Mihomo binary 做完整 boot/connect smoke test。

## 安全設計

- 不提交 `.ovpn` 原始檔
- 不提交 build 中間產物
- `source_candidates.json` 只保存節點 metadata，不保存完整 profile
- 不混用 OpenVPN 的 username/password 與 cert/key 認證模式
- 只處理 VPN Gate 官方公開 profile 材料
- 生成與驗證失敗時不以失敗產物覆蓋既有訂閱
