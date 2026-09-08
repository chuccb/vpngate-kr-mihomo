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

CSV 的 `OpenVPN_ConfigData_Base64` 不保證一定是 UDP，因此若 CSV profile 是 TCP、無法解析或不存在，會改從官方 server table 找同一 IP 的 UDP endpoint，再由官方 `openvpn_download.aspx` 下載 UDP profile。

## v7.2 生成器優化

`vpngate_kr_mihomo_optimized.py` 使用 v7.1 parser/validator 作為相容性基礎，主要優化候選取得與驗證流程：

- 預設 4 個 worker、每批最多 8 筆
- 每個 worker 擁有自己的 `requests.Session`，可重用 HTTP connection
- 最多只處理填滿所需數量的候選，避免不必要下載
- 平行結果會恢復原始候選優先順序後才做 endpoint 去重，避免「誰先完成誰被選中」造成選擇不穩定
- YAML 輸出與 `source_candidates.json` 使用完全相同的最終 emitted 節點集合
- 最終 Mihomo proxy 數不足安全下限時直接失敗

## Clash Verge Rev / Mihomo 設定

目前生成：

```yaml
mode: rule
find-process-mode: strict
unified-delay: true

proxy-groups:
  - name: KR-LOWEST
    type: url-test
    url: https://www.naver.com/
    interval: 60
    timeout: 3000
    tolerance: 0
    lazy: true
    expected-status: 200
    disable-udp: false

tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
```

`PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST` 用於讓 FreeStyle Reboot 對應到韓國最低延遲群組。

Clash Verge Rev 官方文件指出：系統代理無法代理 UDP，而 TUN 會透過虛擬網卡接管不遵循系統代理的程式，例如遊戲。官方目前的 TUN 預設 stack 是 GVisor；本專案則刻意保留 `system` 作為 Windows 遊戲的保守預設，不宣稱所有環境下都比其他 stack 更快。citeturn111698search0turn111698search1

Windows 使用 TUN 時，Clash Verge Rev 官方文件也提醒網卡/網段衝突與防火牆問題可能造成異常；服務模式可讓一般使用者啟動 TUN。citeturn111698search0turn111698search2

## OpenVPN 相容性

Mihomo 官方目前支援 `proto: udp`、`udp: true`、username/password 或 cert/key 二選一，以及 `tls-auth`、`tls-crypt`、`tls-crypt-v2`、`cipher`、`data-ciphers`、`data-ciphers-fallback`、`auth`、`comp-lzo` 等欄位。生成器盡可能保留 VPN Gate 原始 profile，不為了理論速度擅自改寫加密/傳輸參數。citeturn344992search2

## 延遲與遊戲的限制

GitHub Actions 使用 VPN Gate 官方 CSV Ping，只用於候選篩選；它不是台灣使用者到節點的實際 RTT。

`KR-LOWEST` 的 health-check 是 HTTP/HTTPS 延遲，也不是 FreeStyle Reboot 的遊戲 UDP RTT。它的目的只是讓 Mihomo 在你目前的網路環境中從候選節點裡選出較低延遲的節點。

`url-test` 的 `lazy: true` 表示群組未被選用時不持續進行背景測試；`tolerance: 0` 則維持嚴格的最低延遲偏好。citeturn344992search0turn344992search1

## CI / 發布

GitHub Actions 每 6 小時更新一次，也支援手動執行。

Pull Request 會先生成並驗證訂閱，但不發布到 `main`。

正式 `main` 流程在生成與驗證全部成功後才更新 `vpngate_kr_mihomo.yaml`，並保留 push race retry。

CI 除了 PyYAML 語意驗證，還會使用官方 `metacubex/mihomo:v1.19.30` 容器實際執行 `mihomo -t` 檢查生成的配置語法。Mihomo 官方 release 目前可見 v1.19.30，且 v1.19.29 起也已包含 OpenVPN data-ciphers / tls-crypt-v2 等相關能力。citeturn786501search0turn815247view0

注意：CI 的 `-t` 是配置載入測試，不等同於在 GitHub runner 上建立 Windows TUN 並實際連線 VPN Gate；最終 Windows Clash Verge Rev 行為仍應以本機實測為準。

## 安全與資料

- 不提交 `.ovpn` 原始檔
- 不提交完整 OpenVPN profile 中間檔
- `source_candidates.json` 僅保存節點 metadata
- 不混用 OpenVPN 的兩種 authentication mode
- 生成或驗證失敗時不以失敗產物覆蓋正式訂閱
