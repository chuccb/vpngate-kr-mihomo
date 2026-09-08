# VPN Gate KR → Mihomo

自動從 VPN Gate 官方 Korea Republic of server table 篩選 UDP OpenVPN 節點，轉換成可供 Clash Verge Rev / Mihomo 使用的 YAML。

## 訂閱檔

固定檔名：`vpngate_kr_mihomo.yaml`

目前固定訂閱來源：

`https://raw.githubusercontent.com/chuccb/vpngate-kr-mihomo/main/vpngate_kr_mihomo.yaml`

## 目前規則

- Korea Republic of
- VPN Gate 官方 server table
- Ping < 45 ms
- UDP OpenVPN
- 預設最多 20 個節點
- 依官方 Ping 排序；Speed / Score 只作次要排序
- 產生 `KR-LOWEST` url-test 群組
- 保留 `PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST`
- TUN 預設 `stack: system`
- 產生後重新載入 YAML 驗證必要欄位與 PEM 換行

## VPN Gate 認證

VPN Gate 官方 OpenVPN 下載檔可能同時帶有 inline client certificate/private key 與 `auth-user-pass`。這個專案是公開 repository，因此當 `auth-user-pass` 存在時，一律使用 VPN Gate 公開的 `vpn / vpn` 帳密模式，故意不把 client private key 寫入公開訂閱。

若官方 profile 沒有 `auth-user-pass`，而只能依賴 embedded client private key，公開訂閱會拒絕該節點，而不是把私鑰發布到 GitHub。

## 自動更新

GitHub Actions 每 6 小時重新抓取一次，並在 workflow 驗證成功後才替換訂閱檔。若 VPN Gate 暫時故障、節點不足或產物驗證失敗，會保留上一份可用 YAML。

## Clash Verge Rev / TUN 注意事項

這個 YAML 可以作為完整 Mihomo profile 使用。不過 Clash Verge Rev 本身可能對 TUN 使用 GUI / 全域設定覆寫 profile 中的 TUN 欄位，因此最終生效設定應以 Clash Verge Rev 的實際 core configuration 為準。

`stack: system` 是這個專案為低資源、遊戲 UDP 路徑所採用的預設值；若在你的環境有多個虛擬網卡，`auto-detect-interface: true` 仍可能需要在 Clash Verge Rev 的全域設定中配合調整。

## 延遲測試注意

`KR-LOWEST` 使用 Mihomo 對 `https://www.naver.com/` 的 HTTP health check / url-test。這不是 FreeStyle Reboot 遊戲伺服器的實際 UDP RTT，因此 `KR-LOWEST` 只能當作可用性與一般網路延遲的代理指標，不能視為遊戲內延遲排名。

即使某節點官方 Ping 很低，也不代表經台灣 ISP → VPN Gate → 遊戲伺服器的實際路徑一定最低。

## 安全設計

- 不提交 `.ovpn` 原始檔
- 不提交 `source_candidates.json` 的 build 中間產物
- Public repository 禁止輸出 embedded client private key
- YAML 通過完整結構驗證後才 publish
- 生成失敗不覆蓋上一份成功訂閱
