<div align="center">
<h3>🛡️ RahGozar</h3>
<p>
<img src="https://img.shields.io/badge/Go-1.21+-00ADD8.svg?style=flat&logo=go" alt="Go 1.21+">
<img src="https://img.shields.io/github/license/hoseinlolready/RahGozar?style=flat" />
<img src="https://img.shields.io/badge/Status-Stable-orange.svg" alt="Status">
<a href="https://t.me/HOSEINLOL" target="_blank"><img src="https://img.shields.io/badge/telegram-channel-blue&logo=telegram" /></a>
</p>
<h3>High-Performance Port Tunneling Manager</h3>
<p>A web panel for managing port-forward and obfuscated tunnels.</p>
</div>

## Overview

RahGozar forwards traffic between servers and manages those tunnels from a built-in web panel. It supports plain port forwarding as well as obfuscated client/server tunnels for getting through DPI and filtering, with per-tunnel traffic limits, expiry, and multi-admin access.

## Features

- Built-in web panel for managing every tunnel.
- **Multiple tunnel modes** for getting through DPI / filtering.
- **Client / server roles** — run an entry node in Iran and an exit node abroad, managed from the same panel.
- **Separate upload and download accounting** per tunnel, with live throughput shown in the UI.
- Data limits, with optional **periodic auto-reset** (daily / weekly / monthly).
- Expiry dates per tunnel.
- **Multi-admin**: an owner account manages everything; admin sub-accounts each manage only their own tunnels, fully isolated from one another.
- System stats (memory, CPU load, uptime) on the dashboard.
- Builds for `linux/amd64` and `linux/arm64`.

## Tunnel modes

Each tunnel runs in one of four modes. Modes only apply to `client`/`server` roles (see below); a plain local forward ignores the mode.

| Mode | On the wire | Use it when |
|------|-------------|-------------|
| `tcp` | plain bytes | testing, or a clean path with no inspection |
| `aes` | AES-256-GCM, padded, no fixed header — looks like random data | signature/keyword DPI; nothing to fingerprint |
| `tls` | a real TLS 1.3 session — indistinguishable from HTTPS | **the default recommendation for Iran** |
| `ws` | HTTP/WebSocket frames, optionally over TLS | when you want to ride a CDN (e.g. ArvanCloud) on 80/443 |
| `icmp` | reliable, multiplexed, encrypted stream carried inside ICMP echo (ping) | when TCP/UDP are throttled but ping still works; needs root |
| `sit` | kernel IPv6-in-IPv4 (IP protocol 41) | a fast point-to-point link that sidesteps TCP/UDP inspection; needs root |

For `aes`, `tls`, `ws`, and `icmp` you set a **shared secret** that must match on both the entry and the exit; it authenticates the link and derives the encryption key. `tls`/`ws` also take an optional **SNI/Host** for camouflage. For `ws`, prefix the host with `tls:` (e.g. `tls:example.com`) to run it as WebSocket-over-TLS (wss).

`icmp` and `sit` both require root / CAP_NET_RAW (raw sockets) or CAP_NET_ADMIN (kernel tunnel). For `icmp`, set `sysctl -w net.ipv4.icmp_echo_ignore_all=1` on the exit so the kernel's own ping replies don't add noise (one ICMP exit per server). For `sit`, point each node's target IP at the other's public IP, and keep the entry's and exit's link ports equal.

## Roles — how a two-server setup works

A tunnel's **role** decides what the three connection fields mean:

- **`local`** — plain port forward on this box. `listen_port` → `target`. No tunnel.
- **`server`** (exit / abroad) — accept the tunnel on `listen_port` using the chosen mode, decrypt it, and forward the plaintext to `target` (your real local service, e.g. Xray / 3x-ui).
- **`client`** (entry / Iran) — accept end users as plain TCP on `listen_port`, and tunnel each connection with the chosen mode to `target` (the exit's link port).

```
  User in Iran ──▶ Entry (client role) :userPort ══[ mode ]══▶ Exit (server role) :linkPort ──▶ Xray
                   (RahGozar, Iran VPS)                          (RahGozar, foreign VPS)
```

Both servers run the same binary and panel. On the exit you add a `server` tunnel; on the entry you add a `client` tunnel pointing at the exit's IP and link port, with the **same mode and secret**. Point your VPN clients at the entry's public IP and the user port.

## Install

```bash
sudo bash -c "$(curl -sL https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/scripts/installer.sh)"
```

The installer detects your architecture, downloads the matching binary into `/opt/rahgozar`, walks you through creating the **owner** account, and starts a `systemd` service on port `9090` (override with `RAHGOZAR_PORT`).

Open the panel at `http://<server-ip>:9090`.

## Managing accounts

A `rahgozar` command is installed for day-to-day management:

```
rahgozar add-admin          # create an admin account (or the owner, first run)
rahgozar list-admins        # list accounts
rahgozar del-admin <user>   # delete an admin and all their tunnels
rahgozar status | logs      # service status / live logs
rahgozar restart            # restart the service
```

The owner is the first account created and can never be deleted from the CLI. Owners can create admins from the panel as well as the command line.

## Uninstall

```bash
sudo bash -c "$(curl -sL https://raw.githubusercontent.com/hoseinlolready/RahGozar/refs/heads/main/scripts/uninstaller.sh)"
```

You'll be asked whether to keep or remove the database.

## Building from source

Requires Go 1.21+, `gcc`, and (for the arm64 cross-build) `gcc-aarch64-linux-gnu`.

```bash
./build.sh        # produces dist/rahgozar-linux-amd64 and dist/rahgozar-linux-arm64
```

To run locally during development:

```bash
go run . -db ./rahgozar.db -port 9090
```

On first start with an empty database it prompts for the owner account.

## License

MIT — see [LICENSE](./LICENSE).
