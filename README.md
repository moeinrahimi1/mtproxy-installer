# MTProxy EE-Mode Manager (Multi-Instance)

A single Bash script to **install**, **manage**, and **monitor** [MTProto Proxy](https://core.telegram.org/mtproto/mtproto-standalone) in **EE (Fake-TLS + padding)** mode.

- Run **multiple instances** on one server
- Auto-pick a free **HTTP stats** port per instance
- Print a ready-to-use **`tg://` URI** for Telegram clients
- CPU-aware worker count, idempotent build & setup

---

## ✨ Features

- **EE mode** (Fake-TLS + padding): builds the client secret as `ee<secret><hex(domain)>`.
- **Multi-instance**: each instance is a separate systemd service `mtproxy-<name>.service`.
- **Idempotent**:
  - Skips cloning/building if `/opt/MTProxy/objs/bin/mtproto-proxy` already exists.
  - Skips creating a service if `mtproxy-<name>.service` already exists.
- **CPU-aware**: sets `-M` to your actual **CPU core** count.
- **Stats-port collision safe**: tries `-p 8888`, falls back to a free/random port if taken.
- **Live metrics**: `list` reads the local stats endpoint and shows:
  - `inbound_connections`, `active_inbound_connections`
  - `active_connections`, `active_outbound_connections`, `ready_outbound_connections`
  - `tot_forwarded_queries`, `http_qps`, `qps_get`
  - `workers`

---

## ✅ Requirements

- Ubuntu/Debian with **systemd**
- Root privileges (use `sudo`)
- Open firewall for your chosen **client port** (`-H`), e.g. `443` or `8081`

> The script installs dependencies automatically:  
> `git curl build-essential libssl-dev zlib1g-dev xxd iproute2 lsof ca-certificates`

---

## 📥 Installation

Save the script as `mtproxy.sh` and make it executable:

```bash
sudo curl -fsSLo /usr/local/bin/mtproxy.sh https://raw.githubusercontent.com/moeinrahimi1/mtproxy-installer/main/mtproxy.sh
sudo chmod +x /usr/local/bin/mtproxy.sh
