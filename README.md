# VPN Gate KR → Mihomo

自動從 VPN Gate 官方資料產生 Korea Republic 的 UDP OpenVPN Mihomo 訂閱，主要用途是 Windows + Clash Verge Rev + FreeStyle Reboot。

## 訂閱

`https://raw.githubusercontent.com/chuccb/vpngate-kr-mihomo/main/vpngate_kr_mihomo.yaml`

## 唯一生成器

正式生成器現在只有 `vpngate_kr_mihomo.py`，版本 `8.0`。舊版 v6/v7.2/v7.3 wrapper 已移除，避免多份邏輯互相漂移。

資料來源是 VPN Gate 官方 CSV API 與官方 server table。VPN Gate 明確說公開 server table 是 partial，因此 UDP discovery 採兩層流程：先解析首頁；若指定 IP 沒找到 UDP endpoint，再查 `https://www.vpngate.net/en/?ip=<IP>`；最後下載官方 OpenVPN profile 並重新解析，只有真正的 UDP profile 才會進入候選。

候選條件：`CountryShort=KR`、`CountryLong=Korea Republic of`、官方 CSV Ping `< 40 ms`。依官方 Ping → Speed → Score 排序；平行驗證不改變排序；同一 `(server, port)` 只保留一次；最多 10 個，少於 3 個則停止發布。

## 生成配置

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
    tolerance: 0
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

路由只有 `PROCESS-NAME,FreeStyleReboot.exe,KR-LOWEST` 與 `MATCH,DIRECT`。因此除 FreeStyle Reboot 外，其餘流量維持 DIRECT。

`gstatic generate_204` 是 HTTP health-check，不是 FreeStyle Reboot 遊戲 UDP RTT；GitHub Actions 的 VPN Gate Ping 也不能直接代表台灣到節點的實際 RTT。真正使用時應以本機 Mihomo `/delay` 與遊戲實測交叉驗證。

## OpenVPN 相容性

生成器不為了理論速度擅自改寫 VPN Gate profile 的 cipher、auth、TLS 或 keepalive；只做解析、必要轉換與相容性檢查。`tls-auth + non-SHA1 auth` 目前排除，因正式 CI 以 Mihomo stable v1.19.30 驗證。

Authentication 只允許 username/password 或 cert/key 其中一組；PEM 保留換行；`tls-auth` / `tls-crypt` / `tls-crypt-v2` 的互斥關係、`key-direction`、cipher、auth、compression 與 UDP 屬性都會驗證。

## Windows TUN

預設使用 `stack: system`、`auto-route: true`、`auto-detect-interface: true`。公開訂閱不硬寫 `interface-name`、`strict-route`、DNS hijack、fake-IP、MTU 或 OpenVPN `ip-stack`，因為這些設定對不同 Windows 網路環境的效果不同，不能在沒有實測證據下宣稱一定降低遊戲延遲。

## 本機使用

Python 3.13+：

```powershell
python -m pip install -r requirements.txt
python vpngate_kr_mihomo.py generate --limit 10 --workers 4 --batch-size 8 --out-dir build
python vpngate_kr_mihomo.py validate build/vpngate_kr_mihomo.yaml
```

產物只有 `build/vpngate_kr_mihomo.yaml` 與 `build/source_candidates.json`，不保存 `.ovpn` 中間檔。

## 本機延遲測試

```powershell
python tools/benchmark_clash_verge.py --controller http://127.0.0.1:9090 --repeat 10 --timeout 5000
```

此工具只透過 Mihomo controller 測試現有 KR OpenVPN proxy，不修改配置。

## CI

GitHub Actions 每 6 小時更新，也支援手動執行。流程固定為：測試 → syntax → generate → validate → metadata consistency → 官方 Mihomo v1.19.30 `-t` → 成功後才 publish。Pull Request 不發布正式訂閱。

## 官方資料與文件

- VPN Gate：`https://www.vpngate.net/en/`
- VPN Gate CSV API：`https://www.vpngate.net/api/iphone/`
- Mihomo proxy groups：`https://wiki.metacubex.one/en/config/proxy-groups/`
- Mihomo URL-Test：`https://wiki.metacubex.one/en/config/proxy-groups/url-test/`
- Mihomo TUN：`https://wiki.metacubex.one/en/config/inbound/tun/`
- Mihomo OpenVPN：`https://wiki.metacubex.one/en/config/proxies/openvpn/`
