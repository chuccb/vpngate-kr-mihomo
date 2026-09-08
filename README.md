# VPN Gate KR → Mihomo

自動從 VPN Gate 官方 Korea Republic of server table 篩選 UDP OpenVPN 節點，轉換成可供 Clash Verge Rev / Mihomo 使用的 YAML。

## 訂閱檔

固定檔名：`vpngate_kr_mihomo.yaml`

目前先以 GitHub raw 檔案作為固定訂閱來源：

`https://raw.githubusercontent.com/chuccb/vpngate-kr-mihomo/main/vpngate_kr_mihomo.yaml`

## 目前規則

- Korea Republic of
- VPN Gate 官方頁面資料
- Ping < 45 ms
- UDP OpenVPN
- 預設最多 20 個節點
- 依官方 Ping 排序；Speed / Score 只作次要排序
- 產生 `KR-LOWEST` url-test 群組
- 保留 `PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST`
- TUN 預設 `stack: system`
- 產生後重新載入 YAML 驗證 PEM 換行與必要欄位

## 自動更新

GitHub Actions 每 6 小時重新抓取一次，並在 workflow 驗證成功後才替換訂閱檔。若 VPN Gate 暫時故障、節點不足或產物驗證失敗，會保留上一份可用 YAML。

## 注意

這個訂閱的延遲選擇是 Mihomo 對 `https://www.naver.com/` 的 HTTP `/delay` / url-test，而不是 FreeStyle Reboot 遊戲伺服器的實際 UDP RTT。因此 `KR-LOWEST` 的排序不能直接視為遊戲內延遲排名。
