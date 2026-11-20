# Mi Lumruri

[Русский](README.md) · **English** · [简体中文](README.zh-CN.md)

Selective VPN and DPI bypass for the Xiaomi BE7000 on stock firmware. Paste a link to your [TrustTunnel](https://github.com/TrustTunnel) server and pick services: YouTube, Instagram and ChatGPT go through the VPN, Discord goes direct with Zapret DPI bypass, everything else works as usual.

![Panel overview: VPN is up; route map from devices through the router — services via VPN, services with DPI bypass, all other sites](docs/img/overview.png)

**Router:** Xiaomi BE7000 (RC06), firmware 1.1.38. No reflashing: the package is installed over SSH into internal storage (about 5 MB) and runs on the stock iptables, ipset and dnsmasq.

The panel and the detailed guide are in Russian. **[Install and set up](docs/guide.md)** · [Update or roll back](docs/guide.md#обновление-и-откат) · [Limitations](docs/guide.md#ограничения) · [Uninstall](docs/guide.md#удаление) · [Build the package](docs/build.md)

## Install

Download three files from the [latest release](https://github.com/NooBiToo/mi-lumruri/releases/latest) into one folder: `mi-trusttunnel-*.tar`, `SHA256SUMS` and `install.py`. In that folder run:

```sh
python install.py 192.168.31.1
```

You need Python 3.8+, an OpenSSH client and root SSH access to the router ([how to get it](docs/guide.md#доступ-по-ssh-перед-установкой)). The installer asks for the root password and sets the panel password. The panel is at `https://192.168.31.1:8443/`.

The router's internal storage is small: about 20 MB, of which the firmware uses about 9 MB. If space is tight, the installer installs the new version without keeping the previous one and warns that rollback will not be available.

## Features

| | |
| --- | --- |
| **Server** | Paste a `tt://` link or a `client.toml` file and the fields fill in. The server address can be an IP or a domain. Uses the official `trusttunnel_client` v1.3.0: HTTP/2 or HTTP/3, anti-DPI, custom certificate, TLS profile, client_random prefix or key. If the server is down, listed sites either wait or open directly — your choice. |
| **Sites** | Each service is set to **VPN**, **Zapret** or **Off**. Ready-made lists from [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains), including service subnets, ship with the package and update automatically: from every 6 hours to weekly, or manually only. Your own VPN sites, your own DPI-bypass sites and exceptions are separate lists, one site per line. There is also an "Everything via VPN except exceptions" mode. |
| **Zapret** | nfqws2 from zapret2 with built-in strategies works out of the box. "Find a method" tests strategies on the router and applies the best one only if sites open better with it than without Zapret. You can also pick a method manually, with a separate one for YouTube. Scheduled re-check of the method. |
| **Devices** | All home devices, or only the ones you select from the list of connected devices. |
| **DNS** | Secure DNS (DoH or DoT) for all other sites: Cloudflare, Google, AdGuard, NextDNS, Quad9 (DoT) or your own server. If the server is unreachable, queries temporarily go through your ISP. VPN sites use their own DNS server; queries to it go through the tunnel and can be additionally encrypted (DoH or DoT). A separate page for your own DNS records: a domain and all its subdomains point to an address on your home network, for example a server running Traefik. Ad blocking via the router's DNS: HaGeZi Light, Normal or your own list, updated automatically. |
| **Diagnostics** | One-click check of the service, server connection, internet access through the tunnel, routes, DNS, Zapret and programs stuck in a restart loop. Check a single site: which way it goes and whether it opens. Logs and a report in one click, service restart. |
| **Sign-in** | HTTPS and a password, with an optional second step: an authenticator app code (TOTP). |

Changes are saved automatically. The panel also works well on a phone.

<p>
  <img src="docs/img/sites.png" alt="Sites screen: service tiles with VPN, Zapret or Off" width="68%">
  <img src="docs/img/mobile.png" alt="Overview on a phone in the light theme" width="27%">
</p>

![Diagnostics screen: check results, site check and logs](docs/img/diag.png)

## How it works

1. dnsmasq adds the addresses of listed domains to ipset sets.
2. Using these sets, iptables marks traffic from the selected devices:
   - marked traffic goes to the TrustTunnel client's TUN interface;
   - sites with DPI bypass pass through nfqws2;
   - everything else goes direct.
3. The router resolves VPN-site domains with a DNS server inside the tunnel, so the ISP cannot see or tamper with the answers. Other domains go through the secure DNS of the `mi-tt-dns` program, if enabled.
4. A Rust controller reconciles the rules with the kernel and restores them after a firewall reload.

Details are in the [architecture document](ARCHITECTURE.md) (in Russian).

## Status

The package runs on the BE7000 with firmware 1.1.38: tunnel, selective routing, Zapret, secure DNS and the panel. On-device testing continues. Please report problems in [Issues](https://github.com/NooBiToo/mi-lumruri/issues).

- Only IPv4 is routed: devices with VPN or Zapret rules have no outbound IPv6. Preset DNS servers have IPv6 addresses, but they are used only as a fallback.
- Sites are matched by DNS: a device must use the router as its DNS server. "Secure DNS" (DoH) in a browser bypasses the lists.
- One TrustTunnel server is supported.
- DoT does not work everywhere: many ISPs block port 853.

The full list is in the [guide](docs/guide.md#ограничения).

## For developers

The project used to be called mi-trusttunnel. That name remains in package files, programs and folders on the router (`/data/mi-trusttunnel`), so existing installs update without reinstalling.

- The controller, the admin utility and the `mi-tt-dns` DNS proxy are written in Rust.
- The panel uses Vue 3, TypeScript and PrimeVue.
- On the router it uses the stock nginx, uhttpd, dnsmasq, iptables and ipset. Node.js is only needed on the build machine.
- Changes are tested in a network lab built from stock firmware components.

[Build and tests](docs/build.md) · [Architecture](ARCHITECTURE.md) · [Stage log](VERTICAL-SLICE.md) (all in Russian)

A similar project for OpenWrt: [TrustTunnelOpenWrt](https://github.com/NooBiToo/TrustTunnelOpenWrt). Component licenses are listed in [NOTICE](NOTICE).
