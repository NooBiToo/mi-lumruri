# Installing on Xiaomi BE7000

[Русский](guide.md) · **English** · [简体中文](guide.zh-CN.md)

This guide covers Mi Lumruri version 0.3.3. Internal names have not changed: package files are named `mi-trusttunnel-*.tar`, and on the router the package lives in `/data/mi-trusttunnel` and `/tmp/mi-trusttunnel`.

You need a BE7000 (RC06) with firmware 1.1.38, working root access over SSH from the home network, the installation TAR, and the parameters of your TrustTunnel server. The stock release firmware usually ships with SSH turned off.

## SSH access before installation

On the stock firmware SSH is usually turned off. XMiR-Patcher is a third-party tool that enables SSH access on Xiaomi routers. Its README does not confirm compatibility with the BE7000 (RC06) on firmware 1.1.38 specifically. [XMiR-Patcher project and documentation](https://github.com/openwrt-xiaomi/xmir-patcher)

Once SSH is on, check that you can log in from a computer on the home network. Use your router's LAN address:

```sh
ssh root@192.168.31.1 id -u
```

If you get `no matching host key type found. Their offer: ssh-rsa`, the router offers an old key type that recent OpenSSH has disabled. `install.py` allows it on its own. For manual commands, add this to `~/.ssh/config` (on Windows, `%USERPROFILE%\.ssh\config`):

```
Host 192.168.31.1
  User root
  HostKeyAlgorithms +ssh-rsa
  PubkeyAcceptedAlgorithms +ssh-rsa
```

The answer `0` means root login works and you can run the installer. On `Connection refused`, check the address and whether the SSH service is available. On `Permission denied`, SSH already responds: check the key or the password of the `root` user.

## Quick install from a computer

Download `mi-trusttunnel-*.tar`, `SHA256SUMS` and `install.py` from the [latest release](https://github.com/NooBiToo/mi-lumruri/releases/latest) into one folder (or unpack the ZIP from GitHub Actions). Open a terminal in the folder with `install.py`, the TAR and `SHA256SUMS`. Keep the original file names. On Windows, run:

```powershell
python install.py 192.168.31.1
```

On Linux and macOS, use `python3 install.py 192.168.31.1`. Use your own LAN address. You need Python 3.8+ and an OpenSSH client. The script checks the archive, sends it over SSH and, on the first install, asks you to choose a panel password (at least 12 characters). Compare the certificate fingerprint it prints with the one in your browser. Updates use the same method, and the existing login credentials are kept.

The command also works from the source directory: if there is no package next to it, the script downloads the latest successful build from `main` through an authenticated GitHub CLI (`gh auth login`). To use a TAR you have already downloaded, pass `--package path/to/file.tar`. Its `SHA256SUMS` must be in the same folder.

Next, go to [Configure in the panel](#3-configure-in-the-panel). The manual installation method follows below.

### Installing directly on the router

The script [`tools/device/install-from-github.sh`](../tools/device/install-from-github.sh) downloads the v0.3.3 release package from GitHub directly to the router, verifies its SHA-256 and runs the installer. On the first install it asks for a panel password, and at the end it prints the certificate fingerprint. The router needs access to `github.com`. Copy the script to the router and run it in an SSH session:

```sh
scp -O tools/device/install-from-github.sh root@192.168.31.1:/tmp/
ssh -t root@192.168.31.1 sh /tmp/install-from-github.sh
```

### If there is not enough space in `/data`

The `/data` partition on the BE7000 is small: about 20.6 MB, of which the stock firmware takes about 9 MB. An installed release takes about 4.9 MB. The installer wants space for the new release plus a 2 MiB reserve for the firmware (about 7 MB in total). On update, the previous release stays for rollback.

If there is not enough space, the installer does the following:

1. Deletes old releases except the current one and prints "space on /data: deleted old release …" («место на /data: удалён старый релиз …»).
2. If there is just barely enough space (the release plus 512 KiB, about 5.4 MB), it installs the new version and deletes the previous release after installation. It warns: "low space on /data: the previous release will be deleted after installation, rollback to it will not be available" («на /data мало места: после установки прежний релиз будет удалён, откат на него будет недоступен»). Settings are kept.
3. If there is even less, it stops with the message "/data has … bytes free, at least … needed; store releases on USB" («на /data свободно … байт, нужно не меньше …; храните релизы на USB»). Nothing changes.

To keep rollback available, or if the installer stopped, you can store releases on a USB drive. Settings, keys and autostart stay in `/data`.

Connect the drive and find out where the router mounted it:

```sh
ssh root@192.168.31.1 "grep /mnt/usb /proc/mounts"
```

Pass a directory on that drive to the installer:

```powershell
python install.py 192.168.31.1 --store /mnt/usb-XXXX/mi-trusttunnel
```

For a manual install, `sh install.sh install --store=/mnt/usb-XXXX/mi-trusttunnel` does the same. The choice is remembered: later updates install without `--store`.

What to know about using a drive:

- **The drive is needed when the router boots and when you update.** After startup, the programs run from RAM. If the drive disconnects while running, the service keeps working, and the rules come back after a firewall restart.
- **Without the drive at boot, the service does not start.** The loader waits up to 5 minutes for it. During that time, and if the drive never appears, until the next boot with it, the rules do not apply: devices go to the internet directly and the panel is unavailable.
- **When you move from `/data` to the drive, rollback to the previous release is unavailable** until you install the next version.

## 1. Prepare the package and check the router

Download the package from the [release](https://github.com/NooBiToo/mi-lumruri/releases/latest) or from a successful GitHub Actions build, or build it on your computer. Compare the SHA-256 of the installation TAR with the build summary. For the commands below, rename the verified TAR to `mitt-install.tar`. [Where to download or how to build the package](build.md) (in Russian)

Open a terminal on your computer. In the examples the router address is `192.168.31.1`. Use your own LAN address in all commands and in the panel address.

```sh
ssh root@192.168.31.1 "df -k /data /tmp"
```

The installation TAR is about 5.0 MB. An installed release takes about 4.9 MB of internal storage, and the unpacked programs take about 13.2 MB of RAM. The installer also requires 2 MiB of free space in `/data` and 16 MiB in `/tmp`. On update, the previous release stays for rollback, so `/data` needs room for one more release. If there is none, see [If there is not enough space in `/data`](#if-there-is-not-enough-space-in-data). While the package is copied and unpacked, `/tmp` also holds the archive itself and its contents. For detailed diagnostics, you can run the [read-only compatibility check](../tools/device/preflight.sh).

## 2. Install over SSH

On your computer, open the directory with the prepared TAR and run:

```sh
scp -O mitt-install.tar root@192.168.31.1:/tmp/mitt-install.tar
ssh root@192.168.31.1
```

In the SSH session on the router, run the whole block. The `-O` flag in the previous command turns on the SCP protocol, which the stock Dropbear understands.

```sh
stage=$(mktemp -d /tmp/mitt-install.XXXXXX) &&
  tar xf /tmp/mitt-install.tar -C "$stage" &&
  cd "$stage/mi-trusttunnel" &&
  sh install.sh
```

After a successful install, set up login:

```sh
sh /data/mi-trusttunnel/mitt-boot.sh auth init
openssl x509 -in /data/mi-trusttunnel/etc/tls/cert.pem -noout -fingerprint -sha256
```

Set a panel password of at least 12 characters. Open **`https://192.168.31.1:8443/`** from the home network. On the first login, compare the certificate SHA-256 in the browser with the fingerprint from the SSH session.

### Second factor (TOTP)

By default you log in to the panel with a password only. To turn on one-time codes from an app, run on the router:

```sh
sh /data/mi-trusttunnel/mitt-boot.sh auth reset-totp
sh /data/mi-trusttunnel/mitt-boot.sh auth confirm
```

The first command shows a QR code (scan it with an authenticator app) and prints one-time recovery codes. Store them offline. The second command asks for a code from the app. Until the code is confirmed, panel login is closed.

## 3. Configure in the panel

The panel menu has eight screens: **Overview** («Обзор»), **Sites** («Сайты»), **Devices** («Устройства»), **Server** («Сервер»), **Zapret**, **Custom DNS records** («Свои DNS-записи»), **Diagnostics** («Диагностика») and **Advanced** («Дополнительно»). On a phone, the bottom bar has only Overview, Sites, Devices, Server and More («Ещё»). Zapret, Custom DNS records and Diagnostics open from More.

Changes on the screens save automatically. There is no separate Apply («Применить») button. The **Save** («Сохранить») button exists only on the Server screen. The top bar shows whether the VPN is connected and the save progress: "Saving…" («Сохраняю…»), "Applying on the router" («Применяю на роутере»), "Saved" («Сохранено»). The router applies settings on its own within a few seconds. The top bar also has the **VPN** switch and the Log out («Выйти») button.

Three steps are enough for the first setup:

1. **Server**: paste the server link or client configuration and click Save.
2. **Sites**: select the services to open through the VPN.
3. Open a selected site from any device at home. **Overview** should show that the VPN is connected.

### Server

The TrustTunnel server issues the connection data:

```sh
trusttunnel_endpoint vpn.toml hosts.toml -c <username> -a <IP:port>
```

The command prints a `tt://?…` link. With `--format toml` it outputs a client configuration file (`client.toml`). Paste the link or the file contents into the field of the **Quick setup** («Быстрая настройка») card (later it is called Change server («Сменить сервер»)) and click **Recognize** («Распознать»). The panel shows what it recognized and fills in the Server details («Данные сервера») fields. Check them and click **Save** («Сохранить»). The password is write-only: the panel does not show the saved value. To change the server, paste a new link.

You can also fill in the fields manually. HTTP/3, anti-blocking masking, the certificate, the TLS profile and client_random are hidden under **Advanced parameters** («Дополнительные параметры»). They usually come in the link.

| Field | What to enter |
| --- | --- |
| Server address («Адрес сервера») | IP address or domain name of the server. The TrustTunnel client resolves a domain through the router's DNS |
| Port («Порт») | Port from `listen_address` in `vpn.toml` (usually 443) |
| Server name («Имя сервера») | `hostname` from `[[main_hosts]]` in `hosts.toml`. If the certificate is issued for an IP address, leave it empty |
| Login and password («Логин и пароль») | `username` and `password` from `[[client]]` in `credentials.toml` |
| HTTP/3 | Turn on only if the server accepts HTTP/3 and UDP to it is not blocked. Otherwise HTTP/2 is used |
| Anti-blocking masking (anti-DPI) («Маскировка от блокировок (anti-DPI)») | The `anti_dpi` parameter of the TrustTunnel client. Helps if the ISP interferes with the connection to the server |
| Server certificate («Сертификат сервера») | Only for a self-signed certificate: the contents of the file from `cert_chain_path` (PEM). For a certificate from a public CA, leave it empty |
| TLS profile («Профиль TLS») | The `tls_profile` parameter of the TrustTunnel client: which browser or app the connection imitates. Chrome (default), Chrome Canary, Safari, Firefox, OkHttp (Android), OpenSSL or No masking (BoringSSL) («Без маскировки (BoringSSL)»). Comes in the link if the server uses something other than Chrome |
| client_random prefix or key («Префикс или ключ client_random») | Only if the server admits connections by a `client_random` rule in `rules.toml`: a prefix (`client_random_prefix`) or a key (`client_random_auth_key`). Comes in the link and in `client.toml`. Set only one of them |

The **If the server is unavailable, sites from the list** («Если сервер недоступен, сайты из списка») switch: Do not open («Не открывать», recommended) means the sites wait until the VPN works again and do not go around it. Open directly («Открывать напрямую») means the sites open through the ISP, if they can.

The package includes TrustTunnel client v1.3.0, which works with TrustTunnel server 1.3.1. One TrustTunnel server is supported.

### Sites

In the **What to open through the VPN** («Что открывать через VPN») card, choose a mode:

- **Selected only** («Только выбранные», recommended). Selected services and your own sites go through the VPN. Everything else works as usual.
- **Everything through the VPN** («Всё через VPN»). All internet traffic goes through the VPN, except sites from Do not route through the VPN («Не пускать через VPN») and sites with blocking bypass.

**Services** («Сервисы») are tiles with ready-made lists: YouTube, Instagram and Facebook, Discord, Telegram, ChatGPT and Google AI, TikTok, X and others. Services are split into groups, and there is a search. Each tile has three positions: **VPN** (through the VPN), **Zapret** (directly with blocking bypass) and **Off** («Выкл», like all other sites). Everything blocked in Russia («Всё заблокированное в России») is a large general list. It is enough if you do not know what to choose. For services with their own networks (Telegram, Discord, Meta and others), their IP subnets are turned on together with the service. The Hosting and CDN («Хостинги и CDN») group includes entire hosting networks. Only specialists need it.

**Site lists** («Списки сайтов») shows when the ready-made lists were updated, the Update («Обновить») button and the check frequency. See [Site lists](#site-lists).

Your own domain lists take one address per line. Subdomains are included automatically:

- **Your sites through the VPN** («Свои сайты через VPN»): sites that are not among the services. Available only in Selected only mode.
- **Sites with blocking bypass** («Сайты с обходом блокировок»): open directly, without the VPN, with Zapret. They work even when the VPN is off.
- **Do not route through the VPN** («Не пускать через VPN»): sites that always open directly, for example banks and government services.

**Other sites** («Остальные сайты»; in Everything through the VPN mode it is Sites that do not go through the VPN («Сайты, которые не идут через VPN»)): Directly («Напрямую») or With blocking bypass (Zapret) («С обходом блокировок (Zapret)»). The second option helps when YouTube or Discord are slow or do not open without the VPN. See [Blocking bypass (Zapret)](#blocking-bypass-zapret). The bypass method is set on the Zapret page.

### Devices

- **All devices** («Все устройства», recommended): site settings apply to the whole home network, and new devices are included automatically.
- **Selected only** («Только выбранные»): for example, only the TV and the laptop. Other devices open all sites directly. You select the devices with the Through VPN («Через VPN») switch.

The list is built from connected devices (DHCP leases): name, MAC, IP address and whether the device is online. A long list has a search. In Selected only mode, the pencil button **Rename** («Переименовать») sets a readable name that is only for you. A renamed device is selected automatically.

### Overview

Until the server is configured, Overview («Обзор») shows the Connect a server («Подключите сервер») card with the Set up server («Настроить сервер») button.

After that, the main element is the **Routes** («Маршруты») diagram: devices → router → routes (through the VPN, with blocking bypass, directly) with the services on each. Dots run along active routes, and disabled routes are drawn dashed. The VPN state is an indicator on the router. The Edit («Изменить») link leads to Sites («Сайты»). The card above the diagram appears only when something is wrong, and it explains what to do.

The **VPN** switch at the top of the panel turns the VPN off: all traffic goes directly, while the selection of sites and devices is kept and starts working again when the VPN is turned back on. While the VPN is off, sites with blocking bypass still open with Zapret. If Zapret is on only for all other sites, it turns off together with the VPN.

If the router could not apply the latest settings, the top shows "Settings not applied" («Настройки не применены») and a short reason. The router then runs on the previous settings. If applying the rules itself failed, it keeps the protection on: sites from the VPN list do not open until the settings apply. This usually happens when the tunnel is not up yet: the router retries once a minute and applies the settings as soon as the tunnel is ready.

At the bottom: when the site lists were updated and the **Configure** («Настроить») link to the Sites screen, where you manage them. See [Site lists](#site-lists).

### Custom DNS records

A separate menu page (on a phone, under More («Ещё»)). Enter a domain and an IP address on the home network and click Add («Добавить»). The domain and all its subdomains will resolve to that address, for example for a server with Traefik. Records save automatically. For details, see [DNS](#dns).

### Diagnostics

A separate menu page (on a phone, under More («Ещё»)). The **Check** («Проверить») button runs a check on the router itself. It takes up to 20 seconds and changes nothing. It checks:

- the router service and the TrustTunnel client: whether it is connected to the server and with what latency;
- internet access through the tunnel: the router asks Cloudflare (1.1.1.1) for its external address through the tunnel and directly, and the addresses must differ;
- the route into the tunnel, device traffic sorting and address sets;
- the router's DNS and the attached dnsmasq settings;
- secure DNS for other sites and encrypted DNS through the VPN, if they are on;
- blocking bypass (nfqws2);
- program stability: whether the TrustTunnel client, nfqws2 and the DNS proxy crashed in the last 10 minutes. Three restarts or more means "restarting in a loop" («перезапускаются по кругу»).

Checks that are not needed right now (for example, the VPN is off) are listed in the Not used («Не используется») line.

**Check site** («Проверить сайт») shows which path the router sends a site through (VPN, directly with blocking bypass, or directly) and whether the site responds on that path. Sites with blocking bypass are checked from the router directly: Zapret processes device traffic, not the router's own traffic. The device is not taken into account: "selected devices only" rules are shown as if they applied to all devices.

**Logs** («Журналы») shows the latest entries from the service, the TrustTunnel client and Zapret at the time of the check. They contain no passwords. **Copy report** («Скопировать отчёт») puts the results and logs on the clipboard, which is handy to attach to a problem report. **Restart service** («Перезапустить службу») starts the VPN and blocking bypass again and applies the settings. The connection drops for a few seconds.

### Advanced

Usually you do not need to change anything here. Changes save automatically. On a phone, the top of this screen has links to Zapret, Custom DNS records («Свои DNS-записи») and Diagnostics («Диагностика»).

- **Ad blocking** («Блокировка рекламы»): for all devices at home, through the router's DNS. See [Ad blocking](#ad-blocking).
- **DNS for sites through the VPN** («DNS для сайтов через VPN»): server and encryption. See [DNS](#dns) and [Secure DNS (DoH/DoT)](#secure-dns-dohdot).
- **Secure DNS for other sites** («Защищённый DNS для остальных сайтов»): off, DoH or DoT. See [Secure DNS (DoH/DoT)](#secure-dns-dohdot).
- **Panel login** («Вход в панель»): whether the second factor is on. It is turned on over SSH. See [Second factor (TOTP)](#second-factor-totp).

### Zapret

A separate menu page (on a phone, under More («Ещё»)). The top shows whether blocking bypass works and what it processes. The What to bypass («Что обходить») button leads to Sites («Сайты»). Below is the bypass method **For all sites** («Для всех сайтов») and **For YouTube** («Для YouTube»): Automatic («Автоматически») or one of the ready-made methods chosen manually, plus the Restore automatic («Вернуть автоматический») button. Then come **Find a method** («Подобрать способ») and **Automatic method check** («Автопроверка способа»). See [Blocking bypass (Zapret)](#blocking-bypass-zapret).

### If settings were changed manually

The panel shows the simple settings only if the configuration on the router has its form. After edits through the CLI (`mi-tt-ctl`), or if the settings are left over from an earlier panel version, the message "Settings changed manually" («Настройки изменены вручную») appears. As long as you change nothing, the router runs on those settings. The **Convert to simple form** («Привести к простому виду») button replaces them with the panel's settings.

If the saved settings fail validation, the panel still loads them and offers the same button. A section with issues (for example, Zapret) is replaced with default values. If the settings cannot even be parsed, the panel shows "Router settings cannot be read" («Настройки на роутере не читаются») and builds the simple settings from scratch. You then need to paste the VPN server again. The Zapret section from version 0.2.0 (`multisplit`, `pos`, `tcp_ports`) is read as Automatic («Автоматически»).

## Site lists

The service lists come from the [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) project. A snapshot of the lists is included in the package, so everything works right after installation, even without internet.

The router checks for updates on `raw.githubusercontent.com` on its own, once a day by default. You manage the lists in the **Site lists** («Списки сайтов») card on the Sites («Сайты») screen. It shows when the lists were updated and how the last check ended, the **Update** («Обновить») button (checks immediately, together with the ad blocking list) and the check frequency: every 6 hours, once a day, once a week or manual only. Each downloaded file is checked: a response that does not look like a list, or a list with less than half of the previous entries, is not applied, and the previous one stays. New versions are stored in `/data/mi-trusttunnel/lists` and apply immediately. If there is no connection, the next attempt is in an hour. If `/data` is full or not writable, updates are not saved, the error shows on Overview («Обзор») and in the Site lists card, and the next attempt is also in an hour. With the Manual («Вручную») frequency, the router does not check on its own, only when you click Update.

After you install a new package version, the lists from its snapshot apply until the next check downloads fresh ones.

## Blocking bypass (Zapret)

Zapret (nfqws2 from [zapret2](https://github.com/bol-van/zapret2)) modifies the first packets of a connection so that the ISP's equipment does not recognize the site. It works without the VPN and affects only sites that go directly. Sites from the VPN list do not go through it.

**It works right away.** By default the bypass method is Automatic (recommended) («Автоматически (рекомендуется)»). For each site, nfqws2 starts with the first strategy and moves to the next one if connections to the site fail three times. The strategy sets come from [Zapret-Manager](https://github.com/StressOzz/Zapret-Manager): a general set for HTTPS sites, and separate sets for YouTube, for Discord (including voice over UDP) and for YouTube over QUIC.

**Find a method** («Подобрать способ») is on the Zapret page when blocking bypass is in use and the settings are saved. The router tests strategies on the side without disturbing the network: a separate nfqws2 on its own queue, and test `curl` requests from dedicated ports. Devices at home keep running on the previous setting meanwhile. The targets are YouTube, Discord and a set of hosting providers and CDNs. First comes a check without Zapret, then each strategy of the general set. If YouTube did not open without Zapret, the YouTube strategies are checked separately. A site counts as open if the server responded (with any code except 451) and the response was not cut off. During the search, as in normal operation, Discord sites are handled by the permanent Discord profile, so they do not affect the strategy choice. The search takes a few minutes, and the panel shows progress. If Zapret is not active right now (the VPN is off, or all sites of all devices go through the VPN without exceptions), the button is not shown, and an explanation appears instead.

The best strategy is applied only if it opened more sites than no Zapret. After it is applied, it is checked again. If results got worse, the previous method comes back. The panel shows the result, for example "Opened 47 of 54, without bypass 12" («Открылось 47 из 54, без обхода — 12») and "Best method applied." («Лучший способ применён.»). If nothing better was found, the method does not change, and the panel shows "No method better than no bypass was found; the previous one is kept." («Способа лучше, чем без обхода, не нашлось — оставлен прежний.»). If only a better YouTube method was found, the result shows the numbers from the YouTube check. To return to automatic mode, click **Restore automatic** («Вернуть автоматический») on the Zapret page. If the search is interrupted (service stop, reboot), the previous method is restored.

**Automatic method check** («Автопроверка способа»: off, once a day or once a week) repeats the same search on a schedule, no earlier than 10 minutes after the router boots. If the current method stops helping, it finds a new one. If the new one is worse, it keeps the previous one. The time of the last automatic check is stored in `/data`, so a reboot does not reset the schedule.

The effect depends on the ISP: where there is no filtering, Zapret changes nothing, and where filtering works differently, no strategy may help.

## Secure DNS (DoH/DoT)

The router already resolves sites that go through the VPN inside the tunnel. For other sites (including those with blocking bypass), queries go to the ISP's DNS in plain text by default. The ISP can spoof the answer, and then even Zapret will not help. The **Secure DNS for other sites** («Защищённый DNS для остальных сайтов») switch in Advanced («Дополнительно») (Off, DoH, DoT) sends them over an encrypted channel:

- **DoH** (DNS-over-HTTPS, port 443) is recommended: it looks like regular HTTPS. Servers: Cloudflare, Google, AdGuard DNS, NextDNS (needs a profile ID, 6 characters from your account) or your own server.
- **DoT** (DNS-over-TLS, port 853): ISPs in Russia often block this port entirely. Quad9 is also available here (its DoH works only over HTTP/2, which the package does not include).

For your own server, enter the DoH link (`https://dns.example.com/dns-query`) or the DoT server name (`dns.example.com`) and its IP addresses, up to 4, separated by commas. The router connects to the server by IP, without DNS.

This works through the `mi-tt-dns` program on the router: dnsmasq sends it the queries (`server=127.0.0.1#5453`, `no-resolv`), and it sends them to the chosen server over persistent TLS connections, connecting directly by IP. The built-in servers (except NextDNS) also have IPv6 addresses as a fallback: they are used only if none of the IPv4 addresses responds, so a network without IPv6 loses nothing. Domains of sites through the VPN and custom DNS records are handled as before. TLS is rustls with RustCrypto cryptography and Mozilla root certificates (webpki-roots).

If the server is unavailable (blocked, no connection, or right after boot the router clock is not set yet and the certificate fails verification), the query temporarily goes to the ISP's DNS. Otherwise the whole internet would be gone. Advanced and Diagnostics («Диагностика») show how many answers came through the secure server and how many through the ISP, and the last error.

**DNS encryption through the VPN.** Queries about sites through the VPN already go inside the tunnel, and the ISP cannot see them. Only the segment from the VPN server to the DNS server stays in plain text. The **Encryption** («Шифрование») switch in the DNS for sites through the VPN («DNS для сайтов через VPN») block (Plain («Обычный»), DoH, DoT) encrypts that segment too: a second `mi-tt-dns` instance (port 5454) binds its connections to the tunnel interface `mitt0`, so they cannot leave outside the tunnel. It has no fallback: if the tunnel does not work, queries do not go to the ISP, and sites from the list wait until the VPN works again. Usually you do not need this encryption: the queries already go inside the tunnel. It is available for Cloudflare, Google and AdGuard. Quad9 supports only DoT. NextDNS and a custom address support only plain mode (the server name for the certificate is unknown). Below the switch you can see how many encrypted answers came through the tunnel, or why the server does not respond.

## Ad blocking

It works through the router's DNS: for domains from the ad and tracker list, dnsmasq answers "no such domain" (NXDOMAIN), and the query does not go out. It applies to all devices that get DNS from the router. A browser with its own "Secure DNS" (DoH) bypasses it.

You choose the list in Advanced («Дополнительно»): **HaGeZi Light** (default, about 90 thousand domains, ads and trackers, rarely affects sites), **HaGeZi Normal** (about 200 thousand, broader, may occasionally break individual sites) or a **custom link** («своя ссылка»): an https link to a list of domains or hosts lines (`0.0.0.0 domain`; `#` is a comment), file size up to 12 MiB. The [HaGeZi](https://github.com/hagezi/dns-blocklists) lists (GPL-3.0) are taken in the "domain with subdomains" format.

The router downloads the list on its own: right after you turn it on or change the list, and then at the same frequency as the site lists. The Update («Обновить») button in the Site lists («Списки сайтов») card on Sites («Сайты») updates it too. If the site lists update only manually, the ad list also updates only with this button after the first download (or when you change the list). If the download fails, the next attempt is in an hour. The downloaded list is checked: an HTML page, an empty response, or a file where more than 5% of lines cannot be parsed is not applied, and the previous one stays. Single malformed lines are skipped. The working copy is kept in RAM, and a compressed copy (about 0.6–1.2 MB) is in `/data/mi-trusttunnel/adblock.list.gz`, so blocking works right after a reboot. Advanced shows how many domains are in the list and when it was updated, or why it was not updated.

## DNS

Devices keep getting DNS from the router: DHCP and local names work as before. For domains from the lists, dnsmasq puts the addresses from the answers into rule sets, and the router uses them to choose the route.

The router resolves domains of sites through the VPN via a separate DNS server, and queries to it go through the tunnel. You choose the server on the **Advanced** («Дополнительно») screen in the DNS for sites through the VPN («DNS для сайтов через VPN») block: Cloudflare `1.1.1.1` (default), Quad9 `9.9.9.9`, Google `8.8.8.8`, AdGuard DNS `94.140.14.14`, NextDNS `45.90.28.0` or Custom address («Свой адрес»), any public IPv4 address. For NextDNS, link the IP of your VPN server in your NextDNS account (Linked IP), otherwise the filters do not apply. The router resolves other domains as usual or through [secure DNS](#secure-dns-dohdot).

**Custom DNS records** («Свои DNS-записи»): a domain and all its subdomains resolve to the given IPv4 or IPv6 address, and the query does not go out (dnsmasq `address=/domain/address`). Example: a home server with Traefik on `192.168.31.10` and the domain `home.example.com`. One record covers `traefik.home.example.com`, `pve.home.example.com` and the rest. It works for devices that get DNS from the router. The record applies while the mi-trusttunnel service runs. Do not add such a domain to the lists of sites through the VPN or Zapret: the home server must open directly.

## Fine-tuning via CLI

Under the simple screens runs the controller's rule model: source (device, network, whole LAN) × destination (domain, subnet, group, category) × action (through TrustTunnel, directly, directly with Zapret, block). The panel builds these rules from your answers on the screens. Rules such as "set-top box → block" or different actions for different networks can be set only through `mi-tt-ctl` over SSH. After that, the panel shows "Settings changed manually" («Настройки изменены вручную»).

## Limitations

- **Sites are detected by DNS.** Domains from the lists work only while the device asks the router for DNS. If the device or browser has its own DoH/DoT ("secure DNS") turned on, the router does not see the queries, and the domain lists do not apply to that device. Service IP subnets still work in that case.
- **A domain also matches its subdomains.** This is how dnsmasq fills ipset sets: `example.com` also captures `www.example.com`.
- **Shared CDN IP addresses.** The route is chosen by IP addresses from DNS answers. If another site is served from the same CDN address, it also goes through the VPN.
- **IPv4 only.** IPv6 is not tunneled. Devices with VPN, Zapret or blocking have outbound IPv6 closed.
- **Firewall reload.** A full firewall (fw3) reload removes all iptables chains. For about 1–2 seconds, until the include applies the rules again, traffic goes directly. In the lab this window was 1.2 s.
- **The Zapret method search was tested only in a lab without DPI.** There, all targets open without Zapret, and the search ends, as expected, with "No method better than no bypass was found; the previous one is kept." («Способа лучше, чем без обхода, не нашлось — оставлен прежний.»). Only a check on the router will show how the strategies work against a specific ISP's equipment.
- **Lists update from GitHub.** If `raw.githubusercontent.com` is not reachable directly, the lists from the package or the last downloaded ones apply.
- **One TrustTunnel server.** The stock firmware leaves one mark bit free, so one server is supported.
- **Mark conflict.** The route is chosen by the mark bit `0x4000`. If firmware rules use it (for example, mwan3 sticky rules with several WANs), applying is rejected without changes.
- **Guest networks** are not part of the simple settings.

## Updating and rollback

To update, repeat the quick install, or copy the new TAR and repeat step 2 up to the login setup. Existing settings and the second factor are kept. Releases are stored in `/data/mi-trusttunnel/releases` (or in the `--store` directory): the current and the previous one. Older ones are deleted. A new release needs about 4.9 MB plus a 2 MiB reserve. If that much is not available, the installer deletes old releases, and with very little room it installs the update without keeping the previous release. Rollback is then unavailable. See [If there is not enough space in `/data`](#if-there-is-not-enough-space-in-data).

An update must be signed with the same key as the first install: on the first install the router pins the package's public key and then accepts only packages signed with it. Packages from GitHub releases and GitHub Actions builds are signed with the CI key, and a package built on your own computer is signed with your key from `.tools/keys/`. So you cannot install your own build over an install from a release, or the other way around: the installer answers "package signature or hashes failed verification" («подпись или хэши пакета не прошли проверку»). To switch to a package with a different key, remove the installed one with `sh install.sh uninstall --purge` (settings are deleted too) and install again.

To see the state of the running service, run over SSH:

```sh
sh /data/mi-trusttunnel/mitt-boot.sh status
```

To roll back, run **one** command from the unpacked package directory that contains `install.sh`. If the directory is gone after a reboot, copy and unpack the TAR again. You do not need to run the installation to roll back.

```sh
sh install.sh rollback
```

Rollback is available after you install a second version, if the installer kept the previous release. Without it, the command answers "no previous release to roll back to" («нет предыдущего релиза для отката»). To see the current and previous release, run `sh install.sh status`.

## Uninstalling

From the unpacked package directory that contains `install.sh`:

```sh
sh install.sh uninstall          # keeps settings in /data/mi-trusttunnel/etc
sh install.sh uninstall --purge  # removes settings too
```

Without the package, you can do the same manually over SSH:

```sh
sh /data/mi-trusttunnel/mitt-boot.sh stop
uci -q delete firewall.mitt
uci commit firewall
rm -rf /tmp/mi-trusttunnel /data/mi-trusttunnel
```

The first command stops the services, removes the routing rules and removes the mi-trusttunnel file from the dnsmasq settings. If releases were stored on a USB drive, `install.sh uninstall` deletes them on its own. For a manual uninstall, also delete the directory you passed in `--store`.

Without `--purge`, `/data/mi-trusttunnel` keeps the settings and the pinned signing key, so you can reinstall only a package with the same key.

## If you cannot log in

- **SSH refuses the connection.** Check the LAN address and whether SSH is available on the current firmware. The installer runs inside an SSH session.
- **The installer reports a lack of space.** It prints the required and available space separately for `/data` and `/tmp`. Check both partitions with the command from step 1. If `/data` is the one that is short, move releases to a USB drive. See [If there is not enough space in `/data`](#if-there-is-not-enough-space-in-data).
- **The installer says "package signature or hashes failed verification"** («подпись или хэши пакета не прошли проверку»). The package is damaged or signed with a different key than the installed one (your own build over a release package, or the other way around). See [Updating and rollback](#updating-and-rollback).
- **Overview («Обзор») keeps showing "Settings not applied"** («Настройки не применены»). Open Diagnostics («Диагностика») and click Check («Проверить»): it shows which part does not work. The router saves the report of a failed apply to `/tmp/mi-trusttunnel/run/apply.<tag>.fail.json`. You can attach it to a problem report together with the diagnostics report.
- **The panel rejects the code after a reboot.** Check the time with `date -u`. Wait for the clock to sync or use a one-time recovery code. A TOTP code that was already used is not accepted again.

[Back to the project overview](../README.en.md)
