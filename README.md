<div align="center">
<h3>🛡️ RahGozar</h3>
<p>
<img src="https://img.shields.io/badge/Go-1.21+-00ADD8.svg?style=flat&logo=go" alt="Go 1.21+">
<img src="https://img.shields.io/github/license/hoseinlolready/RahGozar?style=flat" />
<img src="https://img.shields.io/badge/Status-Stable-orange.svg" alt="Status">
<a href="https://t.me/HOSEINLOL" target="_blank"><img src="https://img.shields.io/badge/telegram-channel-blue&logo=telegram" /></a>
</p>
<h3>High-Performance Port Tunneling Manager</h3>
<p>Panel, API, database and forwarding core in a single static executable.</p>
</div>

## Overview

RahGozar forwards an inbound port to a remote target and manages those tunnels from a built-in web panel. The entire application web UI, REST API, SQLite storage, and the TCP forwarding core

## Features

- Built-in web panel, served by the binary itself (no separate web server).
- **Separate upload and download accounting** per tunnel, with live throughput shown in the UI.
- Data limits, with optional **periodic auto-reset** (daily / weekly / monthly).
- Expiry dates per tunnel.
- **Multi-admin**: an owner account manages everything; admin sub-accounts each manage only their own tunnels, fully isolated from one another.
- System stats (memory, CPU load, uptime) on the dashboard.

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

## License

MIT — see [LICENSE](./LICENSE).
