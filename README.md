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

## v7.2 生成器優化

`vpngate_kr_mihomo_optimized.py` 保留 v7.1 parser/validator，主要優化候選取得與驗證：

- 預設 4 個 worker、每批最多 8 筆
- 每個 worker 重用自己的 `requests.Session`
- 僅驗證填滿所需數量的候選，避免不必要下載
- 平行完成順序不影響節點選擇：先恢復 Ping → Speed → Score 優先序，再做 endpoint 去重
- YAML 與 metadata 只記錄真正成功轉換成 Mihomo proxy 的節點
- 最終 proxy 數不足安全下限時直接失敗

## Clash Verge Rev / Mihomo 設定

目前生成：

```yaml
mode: rule
find-process-mode: strict
unified-delay: true

proxy-groups:
  - name: KR-LOWEST
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 60
    timeout: 3000
    tolerance: 0
    lazy: true
    expected-status: 204
    disable-udp: false

tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
```

`PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST` 用於讓 FreeStyle Reboot 對應到韓國最低延遲群組。

Clash Verge Rev 使用 TUN 讓不遵循系統代理的程式（例如遊戲）進入 Mihomo 路由；本專案保留 `stack: system` 作為 Windows 遊戲的保守預設，不宣稱所有環境下都比其他 stack 更快。

## OpenVPN 相容性

Mihomo OpenVPN 節點保留 VPN Gate 原始 profile 的傳輸與加密設定，不為了理論速度擅自改寫。認證模式、TLS 材料、cipher、data-ciphers、compression 等欄位都會先驗證再輸出。

## 延遲與遊戲的限制

GitHub Actions 使用 VPN Gate 官方 CSV Ping，只用於候選篩選；它不是台灣使用者到節點的實際 RTT。

`KR-LOWEST` 使用 `http://www.gstatic.com/generate_204` 做 HTTP health-check，要求 HTTP **204**。這是用來讓 Mihomo 在你目前網路環境中選擇較低延遲的可用節點，不等同於 FreeStyle Reboot 的遊戲 UDP RTT。

`lazy: true` 可避免未使用群組時持續進行背景測試；`tolerance: 0` 維持嚴格最低延遲偏好。

## CI / 發布

GitHub Actions 每 6 小時更新一次，也支援手動執行。

Pull Request 只做生成與驗證，不發布到 `main`。正式流程通過全部驗證後才更新訂閱，並保留 push race retry。

CI 同時做 PyYAML 語意驗證，以及使用官方 Mihomo image 執行 `mihomo -t` 配置載入測試。

`mihomo -t` 只驗證配置能被 core 載入，不等同於 GitHub runner 上建立 Windows TUN 或實際連線 VPN Gate。

## 安全與資料

- 不提交 `.ovpn` 原始檔
- 不提交完整 OpenVPN profile 中間檔
- `source_candidates.json` 僅保存節點 metadata
- 不混用 OpenVPN 的兩種 authentication mode
- 生成或驗證失敗時不以失敗產物覆蓋正式訂閱
