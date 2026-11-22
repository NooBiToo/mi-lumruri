# Installing on Xiaomi BE7000

[Русский](guide.md) · **English** · [简体中文](guide.zh-CN.md)

This guide covers Mi Lumruri version 0.8.0. Package files are named `mi-lumruri-*.tar`, and on the router the package lives in `/data/mi-lumruri` and `/tmp/mi-lumruri`. Before 0.5.0 the project was called mi-trusttunnel: installing 0.5.0 over an earlier version moves `/data/mi-trusttunnel` to `/data/mi-lumruri` with all settings and leaves a link in the old place. Next to the main package the release carries a copy named `mi-trusttunnel-*.tar`, which the panel updater of version 0.4 looks for.

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

Download `mi-lumruri-*.tar`, `SHA256SUMS` and `install.py` from the [latest release](https://github.com/NooBiToo/mi-lumruri/releases/latest) into one folder (or unpack the ZIP from GitHub Actions). Open a terminal in the folder with `install.py`, the TAR and `SHA256SUMS`. Keep the original file names. On Windows, run:

```powershell
python install.py 192.168.31.1
```

On Linux and macOS, use `python3 install.py 192.168.31.1`. Use your own LAN address. You need Python 3.8+ and an OpenSSH client. The script checks the archive, sends it over SSH and, on the first install, asks you to choose a panel password (at least 12 characters). Compare the certificate fingerprint it prints with the one in your browser. Updates use the same method, and the existing login credentials are kept.

The command also works from the source directory: if there is no package next to it, the script downloads the latest successful build from `main` through an authenticated GitHub CLI (`gh auth login`). To use a TAR you have already downloaded, pass `--package path/to/file.tar`. Its `SHA256SUMS` must be in the same folder.

Next, go to [Configure in the panel](#3-configure-in-the-panel). The manual installation method follows below.

### Installing directly on the router

The script [`tools/device/install-from-github.sh`](../tools/device/install-from-github.sh) downloads the release package whose URL is written in the script from GitHub directly to the router, verifies its SHA-256 and runs the installer. On the first install it asks for a panel password, and at the end it prints the certificate fingerprint. The router needs access to `github.com`. Copy the script to the router and run it in an SSH session:

```sh
scp -O tools/device/install-from-github.sh root@192.168.31.1:/tmp/
ssh -t root@192.168.31.1 sh /tmp/install-from-github.sh
```

### If there is not enough space in `/data`

The `/data` partition on the BE7000 is small: about 20.6 MB, of which the stock firmware takes about 9 MB. An installed release takes about 4.5 MB. The installer wants space for the new release plus a 2 MiB reserve for the firmware (about 6.5 MB in total). On update, the previous release stays for rollback.

If there is not enough space, the installer does the following:

1. Deletes old releases except the current one and prints "space on /data: deleted old release …" («место на /data: удалён старый релиз …»).
2. If there is just barely enough space (the release plus 512 KiB, about 5 MB), it installs the new version and deletes the previous release after installation. It warns: "low space on /data: the previous release will be deleted after installation, rollback to it will not be available" («на /data мало места: после установки прежний релиз будет удалён, откат на него будет недоступен»). Settings are kept.
3. If there is even less, it stops with the message "/data has … bytes free, at least … needed; store releases on USB" («на /data свободно … байт, нужно не меньше …; храните релизы на USB»). Nothing changes.

To keep rollback available, or if the installer stopped, you can store releases on a USB drive. Settings, keys and autostart stay in `/data`.

Connect the drive and find out where the router mounted it:

```sh
ssh root@192.168.31.1 "grep /mnt/usb /proc/mounts"
```

Pass a directory on that drive to the installer:

```powershell
python install.py 192.168.31.1 --store /mnt/usb-XXXX/mi-lumruri
```

For a manual install, `sh install.sh install --store=/mnt/usb-XXXX/mi-lumruri` does the same. The choice is remembered: later updates install without `--store`.

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

The installation TAR is about 4.6 MB. An installed release takes about 4.5 MB of internal storage, and the unpacked programs take about 12.2 MB of RAM. The installer also requires 2 MiB of free space in `/data` and 16 MiB in `/tmp`. On update, the previous release stays for rollback, so `/data` needs room for one more release. If there is none, see [If there is not enough space in `/data`](#if-there-is-not-enough-space-in-data). While the package is copied and unpacked, `/tmp` also holds the archive itself and its contents. For detailed diagnostics, you can run the [read-only compatibility check](../tools/device/preflight.sh).

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
  cd "$stage/mi-lumruri" &&
  sh install.sh
```

After a successful install, set up login:

```sh
sh /data/mi-lumruri/mitt-boot.sh auth init
openssl x509 -in /data/mi-lumruri/etc/tls/cert.pem -noout -fingerprint -sha256
```

Set a panel password of at least 12 characters. Open **`https://192.168.31.1:8443/`** from the home network. On the first login, compare the certificate SHA-256 in the browser with the fingerprint from the SSH session.

### Second factor (TOTP)

By default you log in to the panel with a password only. To turn on one-time codes from an app, run on the router:

```sh
sh /data/mi-lumruri/mitt-boot.sh auth reset-totp
sh /data/mi-lumruri/mitt-boot.sh auth confirm
```

The first command shows a QR code (scan it with an authenticator app) and prints one-time recovery codes. Store them offline. The second command asks for a code from the app. Until the code is confirmed, panel login is closed.

## 3. Configure in the panel

The panel menu has eight screens: **Overview**, **Sites**, **Devices**, **Server**, **Zapret**, **Custom DNS records**, **Diagnostics** and **Advanced**. On a phone, the bottom bar has only Overview, Sites, Devices, Server and More. Zapret, Custom DNS records and Diagnostics open from More.

Changes on the screens save automatically. There is no separate Apply button. The **Save** button exists only on the Server screen. The top bar shows whether the VPN is connected and the save progress: "Saving…", "Applying on the router", "Saved". The router applies settings on its own within a few seconds. The top bar also has the **VPN** switch and the Sign out button.

The panel is available in Russian, English and Simplified Chinese. At first it picks the language from your browser. You can change it in Advanced and on the sign-in screen, and the choice is remembered in that browser. Detailed diagnostics lines sent by the router stay in Russian.

Three steps are enough for the first setup:

1. **Server**: paste the server link or client configuration and click Save.
2. **Sites**: select the services to open through the VPN.
3. Open a selected site from any device at home. **Overview** should show that the VPN is connected.

### Server

The TrustTunnel server issues the connection data:

```sh
trusttunnel_endpoint vpn.toml hosts.toml -c <username> -a <IP:port>
```

The command prints a `tt://?…` link. With `--format toml` it outputs a client configuration file (`client.toml`). Paste the link or the file contents into the field of the **Quick setup** card (later it is called Change server) and click **Recognize**. The panel shows what it recognized and fills in the Server details fields. Check them and click **Save**. The password is write-only: the panel does not show the saved value. To change the server, paste a new link.

You can also fill in the fields manually. HTTP/3, anti-DPI, the certificate, the TLS profile and client_random are hidden under **Advanced settings**. They usually come in the link.

| Field | What to enter |
| --- | --- |
| Server address | IP address or domain name of the server. The TrustTunnel client resolves a domain through the router's DNS. See also [If the connection to the server drops](#if-the-connection-to-the-server-drops) |
| Port | Port from `listen_address` in `vpn.toml` (usually 443) |
| Server name | `hostname` from `[[main_hosts]]` in `hosts.toml`. If the certificate is issued for an IP address, leave it empty |
| Username and Password | `username` and `password` from `[[client]]` in `credentials.toml` |
| HTTP/3 | Turn on only if the server accepts HTTP/3 and UDP to it is not blocked. Otherwise HTTP/2 is used |
| Blocking evasion (anti-DPI) | The `anti_dpi` parameter of the TrustTunnel client. Helps if the ISP interferes with the connection to the server |
| Server certificate | Only for a self-signed certificate: the contents of the file from `cert_chain_path` (PEM). For a certificate from a public CA, leave it empty |
| TLS profile | The `tls_profile` parameter of the TrustTunnel client: which browser or app the connection imitates. Chrome (default), Chrome Canary, Safari, Firefox, OkHttp (Android), OpenSSL or No disguise (BoringSSL). Comes in the link if the server uses something other than Chrome |
| client_random prefix or client_random key | Only if the server admits connections by a `client_random` rule in `rules.toml`: a prefix (`client_random_prefix`) or a key (`client_random_auth_key`). Comes in the link and in `client.toml`. Set only one of them |
| Subscription link | TrustTunnel 1.3 subscription (`[subscription]` in the server's `vpn.toml`, tag `0x0E` of the `tt://` link). The router uses it to fetch the address, server name, username, password, HTTP/3, anti-DPI, certificate and client_random prefix on its own: on the site list schedule and when you click Update from subscription. If something changed, it applies it. You can also paste a link that contains only the subscription: the router gets the address and password after you save. The link contains the username and password, so it is stored only on the router. The subscription does not change the TLS profile or the client_random key |

The **If the server is unavailable, sites from the list** switch: Don't open (recommended) means the sites wait until the VPN works again and do not go around it. Open directly means the sites open through the ISP, if they can.

The package includes TrustTunnel client v1.3.0, which works with TrustTunnel server 1.3.1.

#### Backup server

The **Backup server** card appears on the Server screen after you save the main server. Click Add, paste the link or `client.toml` of the backup server and click Recognize, or fill in the address, port, server name, username, password and anti-DPI manually. Then click Save. As with the main server, the password is stored only on the router.

If the main server does not connect for 2 minutes, the router switches to the backup. While the backup is in use, the router checks every 5 minutes whether the main server responds. After two successful checks in a row, it returns to the main server. If the backup does not connect either, the router tries the main server again after 2 minutes, and so on in turn. On each switch the client restarts, and the connection drops for a few seconds. While the backup is in use, the card says "the backup is connected now". The Remove backup server button removes it together with its password.

The **Connect to the server with lower latency** switch in the same card changes how the router returns. Every half hour it measures latency to both servers (the TCP connect time from the router) and moves to a noticeably faster one: 30% faster and at least 20 ms, two measurements in a row. The measurement then decides when to return to the primary, while a server failure still switches immediately.

#### Speed and latency

The **Speed and latency** card on the Server screen: the Measure button shows latency to the primary and backup servers and the download speed from the router itself, directly and through the VPN. A measurement downloads up to 50 MB (a file from speed.cloudflare.com) and takes about half a minute.

#### If the connection to the server drops

- **DNS does not respond at startup.** If the server is set by domain, the router remembers its IP address after a successful connection. On the next start, the client gets the domain and this address as a fallback. If DNS does not respond at that moment, the client connects by IP and does not exit with an error.
- **The client is "connected", but traffic does not flow.** A watchdog keeps an eye on the tunnel. Once a minute, while the TrustTunnel client reports "connected", the router makes a short HTTPS request through the tunnel: to 1.1.1.1, and if that fails, to 8.8.8.8. If three checks in a row fail, the router restarts the client, but no more than once every 5 minutes. While the client reconnects to the server on its own, the watchdog does not interfere. The result of the last check is shown in Diagnostics in the Tunnel watchdog line.
- **The server is unavailable for more than 2 minutes.** If a backup server is set, the router switches to it. See above.

### Sites

In the **What to open via VPN** card, choose a mode:

- **Selected only** (recommended). Selected services and your own sites go through the VPN. Everything else works as usual.
- **Everything via VPN**. All internet traffic goes through the VPN, except sites from Keep off VPN and sites with DPI bypass. IPv6 stays closed in this mode until [IPv6 via VPN](#ipv6-via-vpn) is turned on in Advanced.

If only one device needs all its internet through the VPN, keep Selected only and turn on Whole internet for that device on the [Devices](#devices) screen.

**Services** are tiles with ready-made lists: YouTube, Instagram and Facebook, Discord, Telegram, ChatGPT and Google AI, TikTok, X and others. Services are split into groups, and there is a search. Each tile has three positions: **VPN** (through the VPN), **Zapret** (directly with DPI bypass) and **Off** (like all other sites). Everything blocked in Russia is a large general list. It is enough if you do not know what to choose. For services with their own networks (Telegram, Discord, Meta and others), their IP subnets are turned on together with the service. The Hosting and CDN group includes entire hosting networks. Only specialists need it.

**Site lists** shows when the ready-made lists were updated, the Update button and the check frequency. See [Site lists](#site-lists).

Your own domain lists take one address per line. Subdomains are included automatically:

- **Your sites via VPN**: sites that are not among the services. Available only in Selected only mode.
- **Sites with DPI bypass**: open directly, without the VPN, with Zapret. They work even when the VPN is off.
- **Keep off VPN**: sites that always open directly, for example banks and government services.

**Other sites** (in Everything via VPN mode it is Sites that don't go via VPN): Direct or With DPI bypass (Zapret). The second option helps when YouTube or Discord are slow or do not open without the VPN. See [DPI bypass (Zapret)](#dpi-bypass-zapret). The bypass method is set on the Zapret page.

### Devices

- **All devices** (recommended): site settings apply to the whole home network, and new devices are included automatically.
- **Selected only**: for example, only the TV and the laptop. Other devices open all sites directly. You select the devices with the Via VPN switch.

The list is built from connected devices (DHCP leases): name, MAC, IP address and whether the device is online. A long list has a search. In Selected only mode, the pencil button **Rename** sets a readable name that is only for you. A renamed device is selected automatically.

**Whole internet** is a switch on each device when the Sites screen is in Selected only mode. For such a device, all sites go through the VPN, not only the selected ones. Keep off VPN and sites with DPI bypass still apply to it. The switch also works in All devices mode, for example for a TV that needs all its internet through the VPN while the other devices send only the selected sites through the VPN.

### Overview

Until the server is configured, Overview shows the Connect a server card with the Set up server button.

After that, the main element is the **Routes** diagram: devices → router → routes (through the VPN, with DPI bypass, directly) with the services on each. Dots run along active routes, and disabled routes are drawn dashed. The VPN state is an indicator on the router. The Change link leads to Sites. The card above the diagram appears only when something is wrong, and it explains what to do.

The **VPN** switch at the top of the panel turns the VPN off: all traffic goes directly, while the selection of sites and devices is kept and starts working again when the VPN is turned back on. While the VPN is off, sites with DPI bypass still open with Zapret. If Zapret is on only for all other sites, it turns off together with the VPN.

If the router could not apply the latest settings, the top shows "Settings not applied" and a short reason. The router then runs on the previous settings. If applying the rules itself failed, it keeps the protection on: sites from the VPN list do not open until the settings apply. This usually happens when the tunnel is not up yet: the router retries once a minute and applies the settings as soon as the tunnel is ready.

At the bottom: when the site lists were updated and the **Configure** link to the Sites screen, where you manage them. See [Site lists](#site-lists).

Below is the **Traffic** card for a day or a week: how much went through the router WAN port (all internet, including encrypted VPN traffic), how much of it was inside the tunnel, an hourly chart and the devices that use the most. Per-device accounting comes from the firmware's own trafficd service. The router takes readings every 5 minutes and keeps the last 7 days; the copy in `/data` is refreshed every hour, so a reboot loses at most an hour.

### Custom DNS records

A separate menu page (on a phone, under More). Enter a domain and an IP address on the home network and click Add. The domain and all its subdomains will resolve to that address, for example for a server with Traefik. Records save automatically. For details, see [DNS](#dns).

### Diagnostics

A separate menu page (on a phone, under More). The **Check** button runs a check on the router itself. It takes up to 20 seconds and changes nothing. It checks:

- autostart: whether the service is registered in the firewall settings, that is, whether it starts after a router reboot, and the router firmware (a warning if it is not 1.1.38 or was recently updated);
- the router service and the TrustTunnel client: whether it is connected to the server, with what latency, how long it has been connected and which client version runs;
- the tunnel watchdog: when the last check through the tunnel ran, whether it passed, and whether the watchdog restarted the client in the last hour;
- internet access through the tunnel: the router asks Cloudflare (1.1.1.1) for its external address through the tunnel and directly, and the addresses must differ;
- the route into the tunnel, device traffic sorting and address sets;
- the router's DNS and the attached dnsmasq settings;
- secure DNS for other sites and encrypted DNS through the VPN, if they are on;
- DPI bypass (nfqws2);
- program stability: whether the TrustTunnel client, nfqws2 and the DNS proxy crashed in the last 10 minutes. Three restarts or more means "restarting in a loop" («перезапускаются по кругу»).

Checks that are not needed right now (for example, the VPN is off) are listed in the Not in use line. The details in the check lines come from the router, so they are in Russian whatever the panel language.

**Check a site** shows which path the router sends a site through (VPN, directly with DPI bypass, or directly) and whether the site responds on that path. Sites with DPI bypass are checked from the router directly: Zapret processes device traffic, not the router's own traffic. The device is not taken into account: "selected devices only" rules are shown as if they applied to all devices.

**Logs** shows the latest entries from the service, the TrustTunnel client and Zapret at the time of the check. They contain no passwords. **Copy report** puts the results and logs on the clipboard, which is handy to attach to a problem report. **Restart the service** starts the VPN and DPI bypass again and applies the settings. The connection drops for a few seconds.

### Advanced

Usually you do not need to change anything here. Changes save automatically. On a phone, the top of this screen has links to Zapret, Custom DNS records and Diagnostics.

- **Ad blocking**: for all devices at home, through the router's DNS. See [Ad blocking](#ad-blocking).
- **DNS for sites through the VPN**: server and encryption. See [DNS](#dns) and [Secure DNS (DoH/DoT)](#secure-dns-dohdot).
- **IPv6 via VPN**: IPv6 through the tunnel for devices whose whole internet goes through the VPN. See [IPv6 via VPN](#ipv6-via-vpn).
- **Secure DNS for other sites**: off, DoH or DoT. See [Secure DNS (DoH/DoT)](#secure-dns-dohdot).
- **Interface language**: Русский, English or 简体中文. The choice is remembered in this browser.
- **Update**: the installed version, and checking for and installing a new version from GitHub. See [Updating and rollback](#updating-and-rollback).
- **Settings backup**: see [Settings backup](#settings-backup).
- **Telegram notifications**: see [Telegram notifications](#telegram-notifications).
- **Panel sign-in**: whether the second factor is on. It is turned on over SSH. See [Second factor (TOTP)](#second-factor-totp).

### Zapret

A separate menu page (on a phone, under More). The top shows whether DPI bypass works and what it processes. The What to bypass button leads to Sites. Below is the bypass method **For all sites** and **For YouTube**: Automatic or one of the ready-made methods chosen manually, plus the Back to automatic button. Then come **Find a method** and **Automatic method check**. See [DPI bypass (Zapret)](#dpi-bypass-zapret).

### If settings were changed manually

The panel shows the simple settings only if the configuration on the router has its form. After edits through the CLI (`mi-tt-ctl`), or if the settings are left over from an earlier panel version, the message "Settings were changed manually" appears. As long as you change nothing, the router runs on those settings. The **Switch to simple settings** button replaces them with the panel's settings.

If the saved settings fail validation, the panel still loads them and offers the same button. A section with issues (for example, Zapret) is replaced with default values. If the settings cannot even be parsed, the panel shows "Settings on the router cannot be read" and builds the simple settings from scratch. You then need to paste the VPN server again. The Zapret section from version 0.2.0 (`multisplit`, `pos`, `tcp_ports`) is read as Automatic.

## Site lists

The service lists come from the [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) project. A snapshot of the lists is included in the package, so everything works right after installation, even without internet.

The router checks for updates on `raw.githubusercontent.com` on its own, once a day by default. You manage the lists in the **Site lists** card on the Sites screen. It shows when the lists were updated and how the last check ended, the **Update** button (checks immediately, together with the ad blocking list) and the check frequency: Every 6 hours, Daily, Weekly or Manually. Each downloaded file is checked: a response that does not look like a list, or a list with less than half of the previous entries, is not applied, and the previous one stays. New versions are stored in `/data/mi-lumruri/lists` and apply immediately. If there is no connection, the next attempt is in an hour. If `/data` is full or not writable, updates are not saved, the error shows on Overview and in the Site lists card, and the next attempt is also in an hour. With the Manually frequency, the router does not check on its own, only when you click Update. On the same schedule and with the same button, the router updates the server parameters from the [subscription link](#server), if one is set.

After you install a new package version, the lists from its snapshot apply until the next check downloads fresh ones.

## DPI bypass (Zapret)

Zapret (nfqws2 from [zapret2](https://github.com/bol-van/zapret2)) modifies the first packets of a connection so that the ISP's equipment does not recognize the site. It works without the VPN and affects only sites that go directly. Sites from the VPN list do not go through it.

**It works right away.** By default the bypass method is Automatic (recommended). For each site, nfqws2 starts with the first strategy and moves to the next one if connections to the site fail three times. The strategy sets come from [Zapret-Manager](https://github.com/StressOzz/Zapret-Manager): a general set for HTTPS sites, and separate sets for YouTube, for Discord (including voice over UDP) and for YouTube over QUIC.

**Find a method** is on the Zapret page when DPI bypass is in use and the settings are saved. The router tests strategies on the side without disturbing the network: a separate nfqws2 on its own queue, and test `curl` requests from dedicated ports. Devices at home keep running on the previous setting meanwhile. The targets are YouTube, Discord and a set of hosting providers and CDNs. First comes a check without Zapret, then each strategy of the general set. If YouTube did not open without Zapret, the YouTube strategies are checked separately. A site counts as open if the server responded (with any code except 451) and the response was not cut off. During the search, as in normal operation, Discord sites are handled by the permanent Discord profile, so they do not affect the strategy choice. The search takes a few minutes, and the panel shows progress. If Zapret is not active right now (the VPN is off, or all sites of all devices go through the VPN without exceptions), the button is not shown, and an explanation appears instead.

The best strategy is applied only if it opened more sites than no Zapret. After it is applied, it is checked again. If results got worse, the previous method comes back. The panel shows the result, for example "47 of 54 opened, without bypass — 12" and "The best method is applied." If nothing better was found, the method does not change, and the panel shows "No method works better than no bypass — the previous one is kept." If only a better YouTube method was found, the result shows the numbers from the YouTube check. To return to automatic mode, click **Back to automatic** on the Zapret page. If the search is interrupted (service stop, reboot), the previous method is restored.

**Automatic method check** (Off, Daily or Weekly) repeats the same search on a schedule, no earlier than 10 minutes after the router boots. If the current method stops helping, it finds a new one. If the new one is worse, it keeps the previous one. The time of the last automatic check is stored in `/data`, so a reboot does not reset the schedule.

The effect depends on the ISP: where there is no filtering, Zapret changes nothing, and where filtering works differently, no strategy may help.

## Secure DNS (DoH/DoT)

The router already resolves sites that go through the VPN inside the tunnel. For other sites (including those with DPI bypass), queries go to the ISP's DNS in plain text by default. The ISP can spoof the answer, and then even Zapret will not help. The **Secure DNS for other sites** switch in Advanced (Off, DoH, DoT) sends them over an encrypted channel:

- **DoH** (DNS-over-HTTPS, port 443) is recommended: it looks like regular HTTPS. Servers: Cloudflare, Google, AdGuard DNS, NextDNS (needs a profile ID, 6 characters from your account) or your own server.
- **DoT** (DNS-over-TLS, port 853): ISPs in Russia often block this port entirely. Quad9 is also available here (its DoH works only over HTTP/2, which the package does not include).

For your own server, enter the DoH link (`https://dns.example.com/dns-query`) or the DoT server name (`dns.example.com`) and its IP addresses, up to 4, separated by commas. The router connects to the server by IP, without DNS.

This works through the `mi-tt-dns` program on the router: dnsmasq sends it the queries (`server=127.0.0.1#5453`, `no-resolv`), and it sends them to the chosen server over persistent TLS connections, connecting directly by IP. The built-in servers (except NextDNS) also have IPv6 addresses as a fallback: they are used only if none of the IPv4 addresses responds, so a network without IPv6 loses nothing. Domains of sites through the VPN and custom DNS records are handled as before. TLS is rustls with RustCrypto cryptography and Mozilla root certificates (webpki-roots).

If the server is unavailable (blocked, no connection, or right after boot the router clock is not set yet and the certificate fails verification), the query temporarily goes to the ISP's DNS. Otherwise the whole internet would be gone. Advanced and Diagnostics show how many answers came through the secure server and how many through the ISP, and the last error.

**DNS encryption through the VPN.** Queries about sites through the VPN already go inside the tunnel, and the ISP cannot see them. Only the segment from the VPN server to the DNS server stays in plain text. The **Encryption** switch in the DNS for sites through the VPN block (Plain, DoH, DoT) encrypts that segment too: a second `mi-tt-dns` instance (port 5454) binds its connections to the tunnel interface `mitt0`, so they cannot leave outside the tunnel. It has no fallback: if the tunnel does not work, queries do not go to the ISP, and sites from the list wait until the VPN works again. Usually you do not need this encryption: the queries already go inside the tunnel. It is available for Cloudflare, Google and AdGuard. Quad9 supports only DoT. NextDNS and a custom address support only plain mode (the server name for the certificate is unknown). Below the switch you can see how many encrypted answers came through the tunnel, or why the server does not respond.

## Ad blocking

It works through the router's DNS: for domains from the ad and tracker list, dnsmasq answers "no such domain" (NXDOMAIN), and the query does not go out. It applies to all devices that get DNS from the router. A browser with its own "Secure DNS" (DoH) bypasses it.

You choose the list in Advanced: **HaGeZi Light** (default, about 90 thousand domains, ads and trackers, rarely affects sites), **HaGeZi Normal** (about 200 thousand, broader, may occasionally break individual sites) or a **Custom link**: an https link to a list of domains or hosts lines (`0.0.0.0 domain`; `#` is a comment), file size up to 12 MiB. The [HaGeZi](https://github.com/hagezi/dns-blocklists) lists (GPL-3.0) are taken in the "domain with subdomains" format.

The router downloads the list on its own: right after you turn it on or change the list, and then at the same frequency as the site lists. The Update button in the Site lists card on Sites updates it too. If the site lists update only manually, the ad list also updates only with this button after the first download (or when you change the list). If the download fails, the next attempt is in an hour. The downloaded list is checked: an HTML page, an empty response, or a file where more than 5% of lines cannot be parsed is not applied, and the previous one stays. Single malformed lines are skipped. The working copy is kept in RAM, and a compressed copy (about 0.6–1.2 MB) is in `/data/mi-lumruri/adblock.list.gz`, so blocking works right after a reboot. Advanced shows how many domains are in the list and when it was updated, or why it was not updated.

## DNS

Devices keep getting DNS from the router: DHCP and local names work as before. For domains from the lists, dnsmasq puts the addresses from the answers into rule sets, and the router uses them to choose the route.

The router resolves domains of sites through the VPN via a separate DNS server, and queries to it go through the tunnel. You choose the server on the **Advanced** screen in the DNS for sites through the VPN block: Cloudflare `1.1.1.1` (default), Quad9 `9.9.9.9`, Google `8.8.8.8`, AdGuard DNS `94.140.14.14`, NextDNS `45.90.28.0` or Custom address, any public IPv4 address. For NextDNS, link the IP of your VPN server in your NextDNS account (Linked IP), otherwise the filters do not apply. The router resolves other domains as usual or through [secure DNS](#secure-dns-dohdot).

**Custom DNS records**: a domain and all its subdomains resolve to the given IPv4 or IPv6 address, and the query does not go out (dnsmasq `address=/domain/address`). Example: a home server with Traefik on `192.168.31.10` and the domain `home.example.com`. One record covers `traefik.home.example.com`, `pve.home.example.com` and the rest. It works for devices that get DNS from the router. The record applies while the Mi Lumruri service runs. Do not add such a domain to the lists of sites through the VPN or Zapret: the home server must open directly.

## IPv6 via VPN

By default IPv6 does not go through the tunnel: devices with VPN, Zapret or blocking rules have outbound IPv6 closed, and they use IPv4. The **IPv6 via VPN** switch in Advanced opens IPv6 through the tunnel for devices whose whole internet goes through the VPN:

- for the whole network or selected devices in Everything via VPN mode;
- for devices that have Whole internet turned on on the Devices screen.

Turn it on only if the VPN server has IPv6. Home network addresses, link-local and multicast do not go into the tunnel. If the tunnel does not work, IPv6 on these devices waits just like the rest of their traffic (or goes directly if Open directly is selected).

What stays the same:

- **Selected sites do not use IPv6.** dnsmasq puts only IPv4 addresses into the sets, so devices that send only selected sites through the VPN still have IPv6 closed.
- **Exceptions go through the tunnel over IPv6.** On devices whose whole internet goes through the VPN, sites from Keep off VPN and sites with DPI bypass open directly over IPv4, but through the tunnel over IPv6: the router does not sort IPv6 by site.

## Fine-tuning via CLI

Under the simple screens runs the controller's rule model: source (device, network, whole LAN) × destination (domain, subnet, group, category) × action (through TrustTunnel, directly, directly with Zapret, block). The panel builds these rules from your answers on the screens. Rules such as "set-top box → block" or different actions for different networks can be set only through `mi-tt-ctl` over SSH. After that, the panel shows "Settings were changed manually".

## Limitations

- **Sites are detected by DNS.** Domains from the lists work only while the device asks the router for DNS. If the device or browser has its own DoH/DoT ("secure DNS") turned on, the router does not see the queries, and the domain lists do not apply to that device. Service IP subnets still work in that case.
- **A domain also matches its subdomains.** This is how dnsmasq fills ipset sets: `example.com` also captures `www.example.com`.
- **Shared CDN IP addresses.** The route is chosen by IP addresses from DNS answers. If another site is served from the same CDN address, it also goes through the VPN.
- **IPv6 only for "whole internet through the VPN".** Sites from the lists are matched by IPv4 only. Devices with VPN, Zapret or blocking rules have outbound IPv6 closed. The exception is devices whose whole internet goes through the VPN, with [IPv6 via VPN](#ipv6-via-vpn) turned on: all their IPv6 goes through the tunnel, including exceptions and sites with DPI bypass. This requires IPv6 on the VPN server.
- **Firewall reload.** A full firewall (fw3) reload removes all iptables chains. For about 1–2 seconds, until the include applies the rules again, traffic goes directly. In the lab this window was 1.2 s.
- **The Zapret method search was tested only in a lab without DPI.** There, all targets open without Zapret, and the search ends, as expected, with "No method works better than no bypass — the previous one is kept." Only a check on the router will show how the strategies work against a specific ISP's equipment.
- **Lists update from GitHub.** If `raw.githubusercontent.com` is not reachable directly, the lists from the package or the last downloaded ones apply.
- **One TrustTunnel server at a time.** The stock firmware leaves one mark bit free, so traffic goes through one server. The backup server replaces the main one rather than running alongside it, and switching takes up to 2 minutes.
- **Mark conflict.** The route is chosen by the mark bit `0x4000`. If firmware rules use it (for example, mwan3 sticky rules with several WANs), applying is rejected without changes.
- **Guest networks** are not part of the simple settings.

## Updating and rollback

**From the panel** (since version 0.4.0). Advanced has an Update block. The router does not look for new versions on its own: the Check button finds the latest release on GitHub. The router needs access to `api.github.com` and `github.com`. If a newer one exists, the Update to … button appears. The router downloads the package itself, compares its SHA-256 with the release's `SHA256SUMS` file, verifies the signature with the pinned key and restarts the service. The panel disappears for about half a minute, and settings are kept. After the restart the router checks for up to 5 minutes that the new version works: the service and the panel are running and, if settings applied without errors before the update, they apply now too. If not, it restores the previous version on its own, and the panel shows "Version … did not start working, so … was restored" with the reason. Automatic rollback works for updates from the panel starting with version 0.6.0 (the check is run by the version already installed). Starting with 0.7.0 the router checks for a new version on its own once a day (or once a week, or only manually; the choice is in the same block). It only checks: if there is a newer version, a mark appears next to Advanced, and with notifications on you get a Telegram message. You install it with the button. If the router runs your own build signed with your key, the panel offers Switch to GitHub releases and update. The router then accepts the package with the GitHub release key (`e4a271890e5643ab`) and pins it. The panel does not accept other keys.

**From a computer.** To update, repeat the quick install, or copy the new TAR and repeat step 2 up to the login setup. Existing settings and the second factor are kept. Releases are stored in `/data/mi-lumruri/releases` (or in the `--store` directory): the current and the previous one. Older ones are deleted. A new release needs about 4.5 MB plus a 2 MiB reserve. If that much is not available, the installer deletes old releases, and with very little room it installs the update without keeping the previous release. Rollback is then unavailable. See [If there is not enough space in `/data`](#if-there-is-not-enough-space-in-data). Files that do not change between versions (usually the TrustTunnel client and nfqws2) are not copied again by a new release; it refers to them in the current one (a hard link), so two releases take noticeably less space in the store. FAT on a USB drive does not support links, so there files are copied as before.

An update must be signed with the same key as the first install: on the first install the router pins the package's public key and then accepts only packages signed with it. Packages from GitHub releases and GitHub Actions builds are signed with the CI key, and a package built on your own computer is signed with your key from `.tools/keys/`. If you install your own build over an install from a release, or the other way around, the installer refuses and shows both fingerprints: "package is signed with a different key: pinned …, package has …" («пакет подписан другим ключом: закреплён …, у пакета …»). To switch to another key, repeat the install with the `--trust-key` flag and the new key's fingerprint from that message:

```sh
python install.py 192.168.31.1 --trust-key <fingerprint>
```

On the router, the same is `sh install.sh install --trust-key=<fingerprint>`. Settings, passwords and keys are kept. The new key is pinned after installation, and from then on the router accepts only packages signed with it. The fingerprint of the GitHub release key is listed in the description of each release.

You can see the currently pinned key on the router:

```sh
/tmp/mi-lumruri/bin/mi-tt-admin release key-fingerprint /data/mi-lumruri/keys/release.pub
```

The answer is a line like `{"ok":true,"key_fingerprint":"…"}`.

To see the state of the running service, run over SSH:

```sh
sh /data/mi-lumruri/mitt-boot.sh status
```

To roll back, run **one** command from the unpacked package directory that contains `install.sh`. If the directory is gone after a reboot, copy and unpack the TAR again. You do not need to run the installation to roll back.

```sh
sh install.sh rollback
```

Rollback is available after you install a second version, if the installer kept the previous release. Without it, the command answers "no previous release to roll back to" («нет предыдущего релиза для отката»). To see the current and previous release, run `sh install.sh status`.

## Telegram notifications

In Advanced → **Telegram notifications**, the router messages you in Telegram when:

- the tunnel went down (the client has not been connected for more than 3 minutes) and when it is back up, and when the watchdog restarted the client;
- the router switched to the backup server or returned to the primary;
- a new package version came out, an update was installed or rolled back;
- the TrustTunnel subscription failed to update or changed the server settings;
- the router started (off by default).

Setup: in Telegram, open @BotFather, send `/newbot` and copy the bot token. Send your bot any message, otherwise it cannot write to you. Get your numeric id from @userinfobot (for a group, add the bot to it; a group id starts with a minus). Paste the token and id into the panel, choose the events and press Send a test.

Messages go through the VPN while the tunnel works, otherwise directly. If Telegram is unreachable, a message waits in a queue and is sent later (for up to a day), so "tunnel is down" arrives as soon as there is a connection. The token is stored only on the router (`secrets.json`), and the panel does not show it. Messages are written in the panel language at the time you save.

## Settings backup

In Advanced → **Settings backup**, the **Download backup** button saves the file `mi-lumruri-backup-<date>.json` to your computer: settings, rules, devices, custom DNS records and your own lists. Server passwords, subscription links and the panel login (password and second factor) go into the backup only if you turn on **Include server passwords and panel login** and set a backup password (at least 8 characters). The router encrypts that part with the backup password using Argon2id and ChaCha20-Poly1305. Without the password it cannot be read or restored. The panel TLS key and the release signing key are not included: they belong to a specific router.

**Restore from file…** replaces the current settings with those from the backup and applies them right away. The router first checks the whole backup and writes nothing if it is damaged, was made by a newer version, or its settings fail validation. If the backup contains passwords, the panel asks for the backup password; the Without passwords button restores settings only. A backup also works for another BE7000: install the package on it, sign in to the panel and restore.

## Uninstalling

From the unpacked package directory that contains `install.sh`:

```sh
sh install.sh uninstall          # keeps settings in /data/mi-lumruri/etc
sh install.sh uninstall --purge  # removes settings too
```

Without the package, you can do the same manually over SSH:

```sh
sh /data/mi-lumruri/mitt-boot.sh stop
uci -q delete firewall.mitt
uci commit firewall
rm -rf /tmp/mi-lumruri /data/mi-lumruri
```

The first command stops the services, removes the routing rules and removes the mi-lumruri file from the dnsmasq settings. If releases were stored on a USB drive, `install.sh uninstall` deletes them on its own. For a manual uninstall, also delete the directory you passed in `--store`.

Without `--purge`, `/data/mi-lumruri` keeps the settings and the pinned signing key. A package with a different key then installs with the `--trust-key` flag.

## After a Xiaomi firmware update

A firmware update or a firewall settings reset can remove the autostart entry (`config include 'mitt'`). While the service runs, it checks this entry every 10 minutes and restores it on its own; Diagnostics shows this in the Autostart line. If the router rebooted after a firmware update and the service did not start, turn SSH on again (a firmware update usually turns it off) and run:

```sh
sh /data/mi-lumruri/mitt-boot.sh repair
```

The command registers autostart again and starts the service. A firmware update does not touch the settings in `/data/mi-lumruri`. The package is tested on firmware 1.1.38; on another one Diagnostics shows a warning in the Router firmware line.

## If you cannot log in

- **SSH refuses the connection.** Check the LAN address and whether SSH is available on the current firmware. The installer runs inside an SSH session.
- **The installer reports a lack of space.** It prints the required and available space separately for `/data` and `/tmp`. Check both partitions with the command from step 1. If `/data` is the one that is short, move releases to a USB drive. See [If there is not enough space in `/data`](#if-there-is-not-enough-space-in-data).
- **The installer says "package signature or hashes failed verification"** («подпись или хэши пакета не прошли проверку»). The package is damaged: download it again. If the installer says "package is signed with a different key" («пакет подписан другим ключом»), it is your own build over a release package, or the other way around: repeat the install with `--trust-key`. See [Updating and rollback](#updating-and-rollback).
- **Overview keeps showing "Settings not applied".** Open Diagnostics and click Check: it shows which part does not work. The router saves the report of a failed apply to `/tmp/mi-lumruri/run/apply.<tag>.fail.json`. You can attach it to a problem report together with the diagnostics report.
- **The panel rejects the code after a reboot.** Check the time with `date -u`. Wait for the clock to sync or use a one-time recovery code. A TOTP code that was already used is not accepted again.

[Back to the project overview](../README.en.md)
