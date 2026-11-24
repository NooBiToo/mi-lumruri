# Mi Lumruri

[Русский](README.md) · [English](README.en.md) · **简体中文**

为原厂固件的小米 BE7000 提供分流 VPN 和 DPI 绕过。粘贴你的 [TrustTunnel](https://github.com/TrustTunnel) 服务器链接，然后勾选服务：YouTube、Instagram 和 ChatGPT 走 VPN，Discord 直连并通过 Zapret 绕过封锁，其他网站照常访问。

![面板概览：VPN 已连接；从设备经路由器出去的路由图——走 VPN 的服务、绕过封锁的服务、其他网站](docs/img/overview.png)

**路由器：** 小米 BE7000（RC06），固件 1.1.38。无需刷机：软件包通过 SSH 安装到内部存储（约 4.5 MB），使用原厂的 iptables、ipset 和 dnsmasq 运行。

**[安装与设置](docs/guide.zh-CN.md)** · [更新或回滚](docs/guide.zh-CN.md#更新与回滚) · [限制](docs/guide.zh-CN.md#限制) · [卸载](docs/guide.zh-CN.md#卸载) · [构建软件包](docs/build.md)（俄语）

## 安装

从[最新发布版](https://github.com/NooBiToo/mi-lumruri/releases/latest)下载三个文件到同一个文件夹：`mi-lumruri-*.tar`、`SHA256SUMS` 和 `install.py`。在该文件夹中运行：

```sh
python install.py 192.168.31.1
```

需要 Python 3.8+、OpenSSH 客户端，以及路由器的 root SSH 权限（[获取方法](docs/guide.zh-CN.md#安装前开启-ssh-访问)）。安装程序会询问 root 密码并设置面板密码。面板地址：`https://192.168.31.1:8443/`。

路由器内部存储空间很小：约 20 MB，其中固件占用约 9 MB。空间紧张时，安装程序会安装新版本但不保留旧版本，并提示将无法回滚。

## 功能

| | |
| --- | --- |
| **服务器** | 粘贴 `tt://` 链接或 `client.toml` 文件，字段会自动填好。服务器地址可以是 IP 或域名。内置官方客户端 `trusttunnel_client` v1.3.0：HTTP/2 或 HTTP/3、anti-DPI、自定义证书、TLS 指纹配置、client_random 前缀或密钥。支持 TrustTunnel 1.3 订阅链接：路由器会自动获取新的服务器参数。备用服务器：主服务器 2 分钟无法连接时，路由器切换到备用服务器，主服务器恢复响应后再切回。服务器不可用时，列表中的网站可以选择等待或直连。最多同时 16 个服务器：「网站」中的服务和设备都可以选择各自的服务器。 |
| **网站** | 每个服务可设为 **VPN**、**Zapret** 或 **关闭**。软件包自带 [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) 现成列表（含服务子网），并自动更新：从每 6 小时到每周一次，或仅手动更新。你自己的 VPN 网站、绕过封锁的网站和例外各自是独立的列表，每行一个网站。还有「除例外外全部走 VPN」模式。还可以让 IPv6 也走 VPN，适用于全部流量走 VPN 的设备。 |
| **Zapret** | 内置策略的 zapret2 nfqws2 开箱即用。「选择方法」会在路由器上测试各种策略，只有当效果比不用 Zapret 更好时才应用最佳策略。也可以手动选择方法，YouTube 可单独设置。可按计划自动复查方法。 |
| **设备** | 家中所有设备，或从已连接设备列表中选择的设备。可以为单台设备开启「全部流量」走 VPN，其他设备则只让所选网站走 VPN。 |
| **DNS** | 其他网站使用安全 DNS（DoH 或 DoT）：Cloudflare、Google、AdGuard、NextDNS、Quad9（DoT）或你自己的服务器。服务器不可用时，查询会暂时经由运营商。VPN 网站使用单独的 DNS 服务器，查询经隧道发送，并可额外加密（DoH 或 DoT）。自定义 DNS 记录有单独页面：域名及其所有子域名指向家庭网络中的地址，例如运行 Traefik 的服务器。通过路由器 DNS 屏蔽广告：HaGeZi Light、Normal 或自定义列表，自动更新。 |
| **诊断** | 一键检查：服务、与服务器的连接和客户端版本、经隧道访问互联网、隧道看门狗、路由、DNS、Zapret，以及反复崩溃重启的程序。检查单个网站：走哪条路径、能否打开。一键获取日志和报告，重启服务。 |
| **登录** | HTTPS 加密码，可选第二步验证：身份验证器应用的验证码（TOTP）。 |
| **面板** | 支持俄语、英语和简体中文，按浏览器语言自动选择，可以在「设置」和登录页面中更改。可从面板更新：路由器自动从 GitHub 下载新的发布版本，校验 SHA-256 和签名后安装，配置会保留。 |

更改会自动保存。面板在手机上也很好用。

<p>
  <img src="docs/img/sites.png" alt="「网站」页面：服务磁贴，可选 VPN、Zapret 或关闭" width="68%">
  <img src="docs/img/mobile.png" alt="手机上的概览页，浅色主题" width="27%">
</p>

![「诊断」页面：检查结果、网站检查和日志](docs/img/diag.png)

<p>
  <img src="docs/img/zapret.png" alt="「Zapret」页面：状态、所有网站和 YouTube 的方法、选择方法与自动复查方法" width="49%">
  <img src="docs/img/server.png" alt="「服务器」页面：粘贴链接、服务器信息，以及包含 TLS 指纹配置和 client_random 的高级参数" width="49%">
</p>

## 工作原理

1. dnsmasq 把列表中域名的地址加入 ipset 集合。
2. iptables 根据这些集合标记所选设备的流量：
   - 被标记的流量进入 TrustTunnel 客户端的 TUN 接口；
   - 绕过封锁的网站经过 nfqws2；
   - 其余流量直连。
3. 路由器用隧道内的 DNS 服务器解析 VPN 网站的域名，运营商无法看到或篡改应答。启用安全 DNS 后，其他域名通过 `mi-tt-dns` 程序的安全 DNS 解析。
4. Rust 编写的控制器会让规则与内核保持一致，并在防火墙重载后恢复规则。

详见[架构文档](ARCHITECTURE.md)（俄语）。

## 状态

软件包已在固件 1.1.38 的 BE7000 上运行：隧道、分流、Zapret、安全 DNS 和面板。设备上的测试仍在继续。发现问题请提交到 [Issues](https://github.com/NooBiToo/mi-lumruri/issues)。

- 列表中的网站只按 IPv4 匹配：设置了 VPN 或 Zapret 规则的设备无法对外使用 IPv6。例外是开启「IPv6 走 VPN」时全部流量走 VPN 的设备：它们的 IPv6 经隧道传输，需要 VPN 服务器支持 IPv6。预设 DNS 服务器带有 IPv6 地址，但仅作为备用路径。
- 网站按 DNS 识别：设备必须使用路由器作为 DNS 服务器。浏览器中的「安全 DNS」（DoH）会绕过列表。
- 同时使用多个服务器会占用 UU 插件（游戏加速器）的标记位；如果 UU 已启用，则占用备用 WAN 的标记位。两者都启用时只有一个服务器工作。备用服务器替代主服务器启用，切换最多需要 2 分钟。
- 「模块」页面目前只显示存储；VLESS、Hysteria2 和 AmneziaWG 模块将在后续版本中提供。
- DoT 并非处处可用：许多运营商封锁了 853 端口。

完整列表见[指南](docs/guide.zh-CN.md#限制)。

## 开发者

项目原名 mi-trusttunnel。自 0.5.0 版本起，安装包和路由器上的文件夹改名为 `mi-lumruri`（`/data/mi-lumruri`、`/tmp/mi-lumruri`）。在 0.4 之上安装新版本时，会把 `/data/mi-trusttunnel` 连同设置、密码和密钥一起移动到 `/data/mi-lumruri`，并在原位置留下链接，因此回滚到 0.4 和旧命令仍然可用。安装包内的程序仍名为 `mi-tt-*`。

- 控制器、管理工具和 DNS 代理用 Rust 编写，并合并为一个程序 `mi-tt`。
- 面板使用 Vue 3、TypeScript 和 PrimeVue。
- 路由器上使用原厂的 nginx、uhttpd、dnsmasq、iptables 和 ipset。只有构建机需要 Node.js。
- 改动在由原厂固件组件搭建的网络实验环境中测试。

[构建与测试](docs/build.md) · [架构](ARCHITECTURE.md) · [阶段日志](VERTICAL-SLICE.md)（均为俄语）

OpenWrt 上的类似项目：[TrustTunnelOpenWrt](https://github.com/NooBiToo/TrustTunnelOpenWrt)。各组件的许可证见 [NOTICE](NOTICE)。
