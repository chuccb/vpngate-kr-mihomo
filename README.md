# VPN Gate KR → Mihomo

自動從 VPN Gate 官方資料取得 Korea Republic of 節點，驗證真正可用的 UDP OpenVPN profile，並產生可供 **Clash Verge Rev / Mihomo** 使用的 YAML。

## 訂閱

固定檔名：`vpngate_kr_mihomo.yaml`

正式來源：

`https://raw.githubusercontent.com/chuccb/vpngate-kr-mihomo/main/vpngate_kr_mihomo.yaml`

## 節點選擇

- 主要資料來源：VPN Gate 官方 CSV API `https://www.vpngate.net/api/iphone/`
- UDP profile fallback：VPN Gate 官方 server table `https://www.vpngate.net/en/`
- `CountryShort = KR` 且 `CountryLong = Korea Republic of`
- VPN Gate 官方 Ping **< 40 ms**
- 僅接受解析後確認為 **UDP OpenVPN** 的 profile
- 最多 10 個節點
- 候選依官方 Ping → Speed → Score 排序
- 去除重複 `(server, port)` UDP endpoint

CSV 的 `OpenVPN_ConfigData_Base64` 不保證一定是 UDP；若 profile 是 TCP、無法解析或不存在，會改從官方 server table 找同一 IP 的 UDP endpoint，再下載真正的 UDP OpenVPN profile。

## v7.3 低延遲遊戲版

正式 CI 現在使用 `vpngate_kr_mihomo_v7_3.py`。它以 v7.2 的候選取得流程為基礎，另外針對 Windows + Clash Verge Rev + UDP 遊戲做收斂：

- 預設 4 個 worker、每批最多 8 筆。
- 每個 worker 重用自己的 `requests.Session`。
- 只有真正需要的候選才下載/解析 UDP profile。
- 平行完成順序不影響 Ping → Speed → Score 的來源優先序。
- 明確記錄 CSV source IP 與最終 OpenVPN profile `server:port`，避免 fallback 後 metadata 誤判。
- Mihomo stable `v1.19.30` 對 `OpenVPN tls-auth` 的非 SHA-1 digest 有已知握手問題，因此 `tls-auth + auth != SHA1` 不進入正式 stable 訂閱；這不是因為 SHA-1 比其他 digest 更快，而是為了避開 stable core 的已知 bug。
- `KR-LOWEST` health-check timeout 從 5000ms 收斂至 **3000ms**，死節點較快被排除。
- `tolerance` 設為 **5ms**：小幅 RTT 抖動不會讓遊戲中頻繁更換節點；只有明顯更快的候選才值得切換。
- `lazy: false`：群組保持預熱，避免遊戲剛開始時才進行第一輪冷啟動 health-check。
- `profile.store-selected: true`：保留上一次群組選擇，讓重新啟動後不必完全從零開始；仍會接受後續 health-check 修正。

這些調整的目標不是保證「任何環境都更快」，而是降低 **平均 RTT + 首包冷啟動 + 節點抖動/換線** 對競技遊戲的綜合影響。

## Clash Verge Rev / Mihomo 設定

目前生成的核心部分：

```yaml
mode: rule
find-process-mode: strict
unified-delay: true
profile:
  store-selected: true

proxy-groups:
  - name: KR-LOWEST
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 60
    timeout: 3000
    tolerance: 5
    lazy: false
    max-failed-times: 2
    expected-status: 204
    disable-udp: false

tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
```

`PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST` 用於讓 FreeStyle Reboot 對應到韓國最低延遲群組。

這個 YAML **包含 TUN 設定，但在 Clash Verge Rev 中 TUN 的最終生效值仍可能由 Verge 的 GUI / 內部 `config.yaml` 覆寫**。因此不要把訂閱中的 `stack`、`strict-route`、DNS hijack 等欄位視為一定會原樣套用；應以 Clash Verge Rev 的「虛擬網卡模式」設定與實際執行時的最終配置為準。

Clash Verge Rev repository：`https://github.com/Clash-Verge-rev/clash-verge-rev`

本專案保留 `stack: system` 作為 Windows 遊戲的實用預設。Mihomo 官方文件：`https://wiki.metacubex.one/en/config/inbound/tun/`

官方文件指出，`system` 使用系統網路協定堆疊；在 Windows 多出口/虛擬網卡環境，應檢查實際 outbound interface。Windows 防火牆也必須允許 Mihomo core；本專案沒有硬寫 `interface-name`，因為公開 subscription 無法知道每台 Windows 的實體 NIC 名稱。

## OpenVPN 相容性

Mihomo OpenVPN 官方文件：`https://wiki.metacubex.one/en/config/proxies/openvpn/`

Mihomo OpenVPN outbound 支援 `proto: udp/tcp`、username/password 或 cert/key 二選一、CA、`tls-auth` / `tls-crypt` / `tls-crypt-v2`、`key-direction`、`cipher`、`data-ciphers`、`data-ciphers-fallback`、`auth`、`comp-lzo`、`ping`、`ping-restart`、`handshake-timeout` 等欄位。生成器不為了理論速度擅自改寫 VPN Gate 原始 profile 的傳輸與加密設定。

VPN Gate 官方也明確建議：如果 UDP 可以使用，一般應優先選 UDP；其 server table 同時提供 hostname 與 IP profile。官方還提醒 server list 偶爾可能含有錯誤 IP，因此本專案仍會以實際下載並解析的 profile endpoint 作最後依據。

## stable Mihomo 的 tls-auth 邊界

Mihomo `v1.19.30` 的 stable release 之後，development branch 修正了 OpenVPN `tls-auth` HMAC digest 應依 `auth` 派生、而不是固定 SHA-1 的問題。相關 issue：`https://github.com/MetaCubeX/mihomo/issues/2992`

因此 v7.3 對 `tls-auth + non-SHA1 auth` 直接排除，而不是輸出一個可能能載入、但實際 handshake 失敗的 profile。這是 stable-core 相容性篩選，不是效能優化。

## 延遲與遊戲的限制

GitHub Actions 使用 VPN Gate 官方 CSV Ping，只用於候選篩選；它不是台灣使用者到節點的實際 RTT。

`KR-LOWEST` 使用 `http://www.gstatic.com/generate_204` 做 HTTP health-check，要求 HTTP **204**。這是用來讓 Mihomo 在你目前網路環境中選擇較低 HTTP 探測延遲的可用節點，不等同於 FreeStyle Reboot 的遊戲 UDP RTT。Mihomo proxy-group 官方文件：`https://wiki.metacubex.one/en/config/proxy-groups/`

`/proxies/{name}/delay` 是 Mihomo 的 HTTP URL delay API：`https://wiki.metacubex.one/en/api/`

因此 v7.3 的 `tolerance: 5` 是穩定性取捨，不是把理論最低 HTTP RTT 最大化；對持續 UDP 遊戲流量，避免因 1～4ms 的短暫波動頻繁換線通常比每輪都追逐絕對最低數字更合理。

`lazy: false` 則刻意選擇預熱，而不是節省所有背景探測；10 個節點每 60 秒一次健康檢查所增加的流量通常很小，換取遊戲啟動時較低的冷啟動風險。`max-failed-times: 2` 保留較快淘汰連續失敗節點的行為。

## Windows TUN 注意事項

Mihomo TUN 官方文件：`https://wiki.metacubex.one/en/config/inbound/tun/`

本專案選擇 `stack: system` 作為 Windows 遊戲的實用預設，而不是宣稱它在所有電腦上都比 `mixed` 更快。若你的機器有 VMware / VirtualBox / Hyper-V / Tailscale / 其他 VPN/Wintun 等多個介面，請確認實際選中的出口介面是否為你的正常實體網路介面。

本專案不強制 `strict-route: true`；它可以改善某些 Windows 多宿主 DNS 情況，但也可能讓部分虛擬化/特殊網路程式出問題，因此應由實際環境決定。

## CI / 發布

GitHub Actions 每 6 小時更新一次，也支援手動執行。

Pull Request 只做生成與驗證，不發布到 `main`。正式流程通過全部驗證後才更新訂閱，並保留 push race retry。

CI 同時做 PyYAML 語意驗證，以及使用官方 Mihomo image 執行 `mihomo -t` 配置載入測試。

目前 CI 的 Mihomo stable 測試版本為 **v1.19.30**；截至 2026-09-12，官方 release page：`https://github.com/MetaCubeX/mihomo/releases`

`mihomo -t` 只驗證配置能被 core 載入，不等同於 GitHub runner 上建立 Windows TUN 或實際連線 VPN Gate。

## 安全與資料

- 不提交 `.ovpn` 原始檔
- 不提交完整 OpenVPN profile 中間檔
- `source_candidates.json` 僅保存節點 metadata
- 不混用 OpenVPN 的兩種 authentication mode
- 生成或驗證失敗時不以失敗產物覆蓋正式訂閱
- repository 中不保留與生成流程無關的殘留測試/哨兵檔案
