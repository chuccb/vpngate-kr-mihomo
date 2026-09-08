# VPN Gate KR → Mihomo

自動從 VPN Gate 官方 Korea Republic of server table 篩選 UDP OpenVPN 節點，轉換成可供 Clash Verge Rev / Mihomo 使用的 YAML。

## 訂閱檔

固定檔名：`vpngate_kr_mihomo.yaml`

目前固定訂閱來源：

`https://raw.githubusercontent.com/chuccb/vpngate-kr-mihomo/main/vpngate_kr_mihomo.yaml`

## 目前規則

- Korea Republic of
- VPN Gate 官方 server table
- 官方 Ping **< 40 ms**（嚴格小於 40，不包含 40）
- UDP OpenVPN
- **最多 10 個節點**
- 節點依官方 Ping 由低到高排序；Speed / Score 只作同延遲下的次要排序
- 只保留一個 `KR-LOWEST` `url-test` 群組，不再建立 `KR-SELECT`
- `KR-LOWEST` 由 Mihomo 依 `https://www.naver.com/` 的實際 health-check 延遲自動選擇最低延遲節點
- `tolerance: 0`，不為了避免切換而容忍較高延遲節點
- `PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST`
- TUN 預設 `stack: system`
- 產生後重新載入 YAML 驗證必要欄位、認證模式、TLS 互斥設定與 PEM 換行

## 為什麼整合成一個群組

原本 `KR-LOWEST` 是自動選最低延遲的 `url-test`，`KR-SELECT` 則是讓你手動選節點的 `select`。兩者同時存在時，FreeStyle Reboot 已經固定走 `KR-LOWEST`，因此 `KR-SELECT` 對這條遊戲規則沒有必要，反而增加操作與配置複雜度。

現在只保留 `KR-LOWEST`，FreeStyle Reboot 直接交給它自動挑最低延遲節點。代價是沒有另外的手動節點選擇群組；如果要手動指定節點，可直接在 Mihomo/Clash Verge Rev 的節點介面選擇單一 proxy。

## 延遲與排序的重要限制

GitHub Actions 篩選節點時使用的是 VPN Gate 官方 server table 顯示的 Ping，因此 `<40ms` 是「VPN Gate 官方 Ping」，不是你的台灣電腦到該節點的實測 RTT。

訂閱載入到 Mihomo 後，`KR-LOWEST` 才會從你的實際網路環境對 `https://www.naver.com/` 進行 health-check，並依實測延遲自動選擇。因此「產生時的節點順序」與「你本機實際使用時的最低延遲」是兩個不同層級的排序。

`KR-LOWEST` 的 HTTP health-check 也不是 FreeStyle Reboot 遊戲伺服器的 UDP RTT，所以不能把它當成遊戲內延遲的絕對排名。

## VPN Gate 認證

VPN Gate 官方 OpenVPN 下載檔可能包含 inline client certificate/private key，也可能使用 `auth-user-pass`。本專案依下載到的官方 profile 決定認證模式：有 `auth-user-pass` 時使用 VPN Gate 公開的 `vpn / vpn`；沒有 `auth-user-pass` 而 profile 本身提供 certificate/key 時，保留官方 profile 所需的 cert/key 組合，並且不與帳密模式混用。

這裡處理的是 VPN Gate 官方公開 profile 中的認證材料，不是讀取或發布使用者自行建立的個人憑證。

## 自動更新

GitHub Actions 每 6 小時重新抓取一次，並在 workflow 驗證成功後才替換訂閱檔。節點不足或產物驗證失敗時，不會以失敗產物覆蓋既有訂閱。

## Clash Verge Rev / TUN 注意事項

這個 YAML 可以作為 Mihomo profile 使用。不過 Clash Verge Rev 本身可能透過 GUI / 全域設定覆寫 profile 中的 TUN 欄位，因此最終生效設定應以 Clash Verge Rev 實際 core configuration 為準。

`stack: system` 是這個專案目前針對低資源與遊戲 UDP 路徑採用的預設值；若 Windows 上存在多個虛擬網卡，`auto-detect-interface: true` 仍可能需要在 Clash Verge Rev 的全域設定中調整。

## 安全設計

- 不提交 `.ovpn` 原始檔
- 不提交 `source_candidates.json` 的 build 中間產物
- 不混用 OpenVPN 的 username/password 與 cert/key 認證模式
- YAML 通過完整結構驗證後才 publish
- 生成失敗不覆蓋上一份成功訂閱
