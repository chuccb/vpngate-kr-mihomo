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
- 不只是取前 10 筆：會持續檢查候選，直到取得 10 個有效 UDP profile 或候選耗盡
- 去除重複的 OpenVPN `(server, port)` endpoint
- 只保留一個 `KR-LOWEST` `url-test` 群組，不建立 `KR-SELECT`
- `KR-LOWEST` 使用 `https://www.naver.com/` 做 Mihomo health-check
- `tolerance: 0`，嚴格偏好最低測得延遲
- `lazy: true`，群組未被實際使用時不持續做背景 health-check
- `disable-udp: false`
- `PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST`
- TUN 預設 `stack: system`

## 為什麼使用「CSV + 官方 UDP endpoint」雙來源

實際整合測試證明，VPN Gate CSV API 的 `OpenVPN_ConfigData_Base64` 並不代表該資料一定是 UDP profile；在實際某次更新中，符合 Korea + Ping < 40 ms 的 27 筆候選裡，多數 API profile 解碼後為 TCP，只有少數可直接作為 UDP 使用。

因此 v7.1 不再假設「CSV 有 OpenVPN profile」就等於「CSV 有 UDP OpenVPN」。現在的流程是：

1. CSV API 提供 Korea 節點、Ping、Speed、Score 與 OpenVPN profile metadata。
2. 先依官方 Ping / Speed / Score 排出候選順序。
3. 若 CSV 的 `OpenVPN_ConfigData_Base64` 解碼後本身就是 UDP，直接使用，不再額外下載。
4. 若 CSV profile 是 TCP 或無法直接使用，則從官方 server table 找同一 IP 的 UDP OpenVPN endpoint。
5. 使用 VPN Gate 官方的 `openvpn_download.aspx` + `udp=1` 下載真正的 UDP `.ovpn`。
6. 再次解析並驗證 profile，成功後才加入候選。
7. 持續往下一個候選檢查，直到湊滿最多 10 個有效 UDP profile。

這樣既以結構化 CSV 作為主要排序依據，又不會錯誤地把 TCP profile 當成 UDP 節點。

## OpenVPN profile 處理

程式不會為了「理論上比較快」而任意修改 VPN Gate profile 的傳輸參數，而是盡可能保留官方 profile 的實際設定。

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
- `ping`、`ping-restart`、`handshake-timeout`、`peer-info`

VPN Gate 公開 profile 可能故意附帶共享／dummy client certificate/key。這類官方公開材料會依 profile 保留；若 profile 使用 `auth-user-pass`，則使用 VPN Gate 公開的 `vpn / vpn` 認證，而且絕不與 cert/key 混用。

## 延遲與排序的重要限制

GitHub Actions 使用的是 VPN Gate 官方 CSV 的 Ping，因此 `<40ms` 是「VPN Gate 官方 Ping」，不是台灣使用者到該 VPN 節點的實際 RTT。

節點載入到 Mihomo 後，`KR-LOWEST` 才會在你的本機網路環境中對 `https://www.naver.com/` 做 health-check，並依實測延遲選擇節點。所以產生時的官方 Ping 只是候選優先順序，並不保證就是你實際遊戲內最低延遲。

HTTP health-check 也不是 FreeStyle Reboot 的遊戲 UDP RTT，因此不能把 Naver 延遲直接當成遊戲 Ping。

## TUN / 遊戲設定

目前產出的 TUN 是：

```yaml
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
```

`system` 是目前針對 Windows 遊戲 UDP 路徑採用的保守預設，不宣稱它在所有環境都是絕對最快。Mihomo 目前也提供 `system`、`gvisor`、`mixed`；多網卡環境還可能需要在 Clash Verge Rev 的全域設定中手動指定 outbound interface。

## 自動更新

GitHub Actions 每 6 小時重新抓取一次。生成、YAML reload 與語意驗證全部成功後才會替換正式訂閱檔。

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

這是 YAML 與語意層驗證；目前沒有宣稱在 GitHub Actions 中啟動真實 Mihomo binary 做完整 boot/connect smoke test。

## 安全設計

- 不提交 `.ovpn` 原始檔
- 不提交 build 中間產物
- `source_candidates.json` 只保存節點 metadata，不保存完整 profile
- 不混用 OpenVPN 的 username/password 與 cert/key 認證模式
- 只處理 VPN Gate 官方公開 profile 材料
- 生成或驗證失敗時不以失敗產物覆蓋既有訂閱
