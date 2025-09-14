#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# MTProxy EE-mode multi-instance installer/manager
#
# Usage:
#   sudo bash mtproxy.sh add     # interactive: add new instance (port -> secret -> tag -> domain)
#   sudo bash mtproxy.sh list    # list all instances, live stats, and tg:// URIs
#
# Notes:
#   - Binary path: /opt/MTProxy/objs/bin/mtproto-proxy
#   - Each instance has:
#       env:   /etc/mtproxy/<name>.env
#       wrap:  /usr/local/sbin/mtproxy-run-<name>
#       svc:   mtproxy-<name>.service
#   - Stats port (-p) is per-instance: tries 8888, falls back to a free port.
#   - EE secret = "ee" + <secret> + hex(<domain>)
# =============================================================================

# ---- helpers ----------------------------------------------------------------
require_root() { if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo $0)"; exit 1; fi; }
ask(){ local p="$1" d="$2" v; read -r -p "$p [$d]: " v || true; echo "${v:-$d}"; }

first_global_ipv4(){
  ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | awk '
    function is_private(ip){split(ip,o,".");return (o[1]==10)||(o[1]==172&&o[2]>=16&&o[2]<=31)||(o[1]==192&&o[2]==168)||(o[1]==169&&o[2]==254)}
    { if (!is_private($1)) { print $1; exit } }'
}

domain_hex(){ echo -n "$1" | xxd -plain; }

cpu_workers(){
  if command -v nproc >/dev/null 2>&1; then nproc
  elif getconf _NPROCESSORS_ONLN >/dev/null 2>&1; then getconf _NPROCESSORS_ONLN
  else echo 2; fi
}

is_port_free(){
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    # ss path: show listening TCP, extract port, compare
    ! ss -ltn 2>/dev/null | awk 'NR>1{print $4}' | awk -F: '{print $NF}' | grep -qx "$port"
  else
    ! lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | awk '{print $9}' | sed -n 's/.*:\([0-9]\+\).*/\1/p' | grep -qx "$port"
  fi
}

find_free_port(){
  local start="${1:-8888}"
  local limit=$((start+2000))
  local p
  for ((p=start; p<=limit; p++)); do
    if is_port_free "$p"; then
      echo "$p"; return 0
    fi
  done
  # last resort: random high port
  shuf -i 20000-65000 -n 1
}

ensure_deps(){
  apt-get update -y
  apt-get install -y --no-install-recommends \
    git curl build-essential libssl-dev zlib1g-dev xxd iproute2 ca-certificates lsof
}

ensure_mtproxy_built(){
  install -d /opt
  if [[ ! -d /opt/MTProxy ]]; then
    echo "[*] Cloning MTProxy (first time)..."
    git clone https://github.com/GetPageSpeed/MTProxy /opt/MTProxy
  else
    echo "[*] MTProxy directory exists: /opt/MTProxy (skipping clone)"
  fi

  local bin="/opt/MTProxy/objs/bin/mtproto-proxy"
  if [[ -x "$bin" ]]; then
    echo "[*] Binary exists: $bin (skipping build)"
  else
    echo "[*] Building MTProxy..."
    (cd /opt/MTProxy && make)
  fi

  local bindir="/opt/MTProxy/objs/bin"
  [[ -f "$bindir/proxy-secret" ]] || curl -fsSL https://core.telegram.org/getProxySecret -o "$bindir/proxy-secret"
  [[ -f "$bindir/proxy-multi.conf" ]] || curl -fsSL https://core.telegram.org/getProxyConfig -o "$bindir/proxy-multi.conf"
}

extract_port_from_cmd() {
  # Parse "-p <port>" or "-p<port>" from a command line string
  local prev="" tok
  for tok in $1; do
    if [[ "$prev" == "-p" ]]; then echo "$tok"; return 0; fi
    if [[ "$tok" =~ ^-p([0-9]+)$ ]]; then echo "${BASH_REMATCH[1]}"; return 0; fi
    prev="$tok"
  done
  return 1
}

detect_stats_port() {
  # Arg: systemd service name (e.g., mtproxy-final.service)
  local svc="$1" pid cmd port
  pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null || echo "")
  if [[ -n "$pid" && "$pid" != "0" ]]; then
    cmd=$(ps -o args= -p "$pid" 2>/dev/null || true)
    port=$(extract_port_from_cmd "$cmd" || true)
    [[ -n "$port" ]] && echo "$port"
  fi
}

fetch_stats(){
  local port="$1" out=""
  out="$(curl -fsS --max-time 1 "http://127.0.0.1:${port}/stats" 2>/dev/null || true)"
  if [[ -z "$out" ]]; then
    out="$(curl -fsS --max-time 1 "http://127.0.0.1:${port}/" 2>/dev/null || true)"
  fi
  echo "$out"
}

stat_get(){
  # usage: stat_get "$blob" "key" -> value or "-"
  local blob="$1" key="$2"
  echo "$blob" | awk -v k="$key" '$1==k {print $2; found=1} END{if(!found)print "-"}'
}

# ---- instance creation ------------------------------------------------------
make_instance(){
  local name port secret tag domain server_ip workers stats_port
  name=$(ask "Instance name (used for systemd: mtproxy-<name>)" "default")
  local svc="mtproxy-${name}"
  local env="/etc/mtproxy/${name}.env"
  local wrap="/usr/local/sbin/mtproxy-run-${name}"

  if systemctl list-unit-files | grep -q "^${svc}.service"; then
    echo "[*] Service ${svc}.service already exists. Skipping creation."
    return 0
  fi

  port=$(ask "Client port to expose via Fake-TLS (-H)" "443")

  # Stats port: try 8888 → next free → random if needed
  local desired_stats=8888
  if is_port_free "$desired_stats"; then
    stats_port="$desired_stats"
  else
    stats_port=$(find_free_port "$desired_stats")
  fi
  echo "[*] HTTP stats will listen on 127.0.0.1:${stats_port}"

  secret=$(head -c 16 /dev/urandom | xxd -ps)
  echo "Generated 16-byte secret (hex) — will be USED: ${secret}"
  tag=$(ask "Proxy tag (-P) for server stats (optional, can be empty)" "")
  domain=$(ask "Fake TLS domain (-D), must support TLS 1.3" "www.google.com")

  server_ip=$(first_global_ipv4 || true)
  if [[ -z "${server_ip:-}" ]]; then
    echo "Could not determine a public IPv4 from 'ip a'."
    server_ip=$(ask "Enter server IPv4 manually" "127.0.0.1")
  fi

  local dhex ee_secret
  dhex=$(domain_hex "${domain}")
  ee_secret="ee${secret}${dhex}"

  workers=$(cpu_workers)
  echo "[*] Using CPU workers: ${workers}"

  # persist env
  install -d -m 0755 /etc/mtproxy
  cat >"${env}" <<EOF
NAME="${name}"
PORT="${port}"
SECRET="${secret}"
FAKE_DOMAIN="${domain}"
PROXY_TAG="${tag}"
BIN="/opt/MTProxy/objs/bin/mtproto-proxy"
BIN_DIR="/opt/MTProxy/objs/bin"
WORKERS="${workers}"
STATS_PORT="${stats_port}"
EOF
  chmod 0644 "${env}"

  # wrapper (unique per instance)
  cat >"${wrap}" <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
source "/etc/mtproxy/${NAME}.env"
cd "${BIN_DIR}"

args=( "${BIN}"
  -u nobody
  -p "${STATS_PORT}"
  -H "${PORT}"
  -S "${SECRET}"
  -D "${FAKE_DOMAIN}"
  --http-stats
  --aes-pwd "${BIN_DIR}/proxy-secret" "${BIN_DIR}/proxy-multi.conf"
  -M "${WORKERS}"
)
if [[ -n "${PROXY_TAG:-}" ]]; then
  args+=( -P "${PROXY_TAG}" )
fi
exec "${args[@]}"
WRAP
  chmod 0755 "${wrap}"

  # systemd unit (unique per instance)
  cat >"/etc/systemd/system/${svc}.service" <<UNIT
[Unit]
Description=MTProto Proxy (EE mode Fake-TLS) [${name}]
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${env}
ExecStart=${wrap}
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now "${svc}.service" || true

  echo
  echo "============================================="
  systemctl --no-pager --full -l status "${svc}.service" || true
  echo "============================================="
  echo

  local uri="tg://proxy?server=${server_ip}&port=${port}&secret=${ee_secret}"
  echo "[OK] Instance: ${name}"
  echo "    Service:     ${svc}.service"
  echo "    Client port: ${port}"
  echo "    Stats port:  127.0.0.1:${stats_port}"
  echo "    Domain:      ${domain}"
  [[ -n "${tag}" ]] && echo "    Tag:         ${tag}"
  echo "    Secret:      ${secret}"
  echo "    EE secret:   ${ee_secret}"
  echo "    URI:         ${uri}"
}

# ---- list -------------------------------------------------------------------
list_instances(){
  local server_ip env
  server_ip=$(first_global_ipv4 || true)
  [[ -z "${server_ip:-}" ]] && server_ip="127.0.0.1"

  shopt -s nullglob
  for env in /etc/mtproxy/*.env; do
    # shellcheck disable=SC1090
    source "${env}"

    local name="${NAME:-$(basename "$env" .env)}"
    local svc="mtproxy-${name}.service"
    local state
    state="$(systemctl is-active "$svc" 2>/dev/null || echo inactive)"

    # derive tg link bits
    local dhex ee uri
    dhex=$(domain_hex "${FAKE_DOMAIN:-}")
    ee="ee${SECRET:-}${dhex}"
    uri="tg://proxy?server=${server_ip}&port=${PORT:-}&secret=${ee}"

    # figure out stats port (env or detect from running cmd)
    local stats_port="${STATS_PORT:-}"
    if [[ -z "$stats_port" ]]; then
      stats_port="$(detect_stats_port "$svc" || true)"
    fi

    # live stats (only if we have a port)
    local stats=""
    if [[ -n "$stats_port" ]]; then
      stats="$(fetch_stats "${stats_port}")"
    fi

    # extract interesting metrics
    local s_inbound s_active_in s_active s_tot_fw s_http_qps s_qps_get s_workers s_ready_out s_outbound s_http_conn
    s_inbound=$(stat_get "$stats" "inbound_connections")
    s_active_in=$(stat_get "$stats" "active_inbound_connections")
    s_active=$(stat_get "$stats" "active_connections")
    s_tot_fw=$(stat_get "$stats" "tot_forwarded_queries")
    s_http_qps=$(stat_get "$stats" "http_qps")
    s_qps_get=$(stat_get "$stats" "qps_get")
    s_workers=$(stat_get "$stats" "workers")
    s_ready_out=$(stat_get "$stats" "ready_outbound_connections")
    s_outbound=$(stat_get "$stats" "active_outbound_connections")
    s_http_conn=$(stat_get "$stats" "http_connections")

    printf "\n== %s ==\n" "$name"
    printf "Service:       %s (%s)\n" "$svc" "$state"
    printf "Client port:   %s\n" "${PORT:-}"
    printf "Stats port:    127.0.0.1:%s\n" "${stats_port:-"-"}"
    printf "Domain:        %s\n" "${FAKE_DOMAIN:-}"
    [[ -n "${PROXY_TAG:-}" ]] && printf "Tag:           %s\n" "${PROXY_TAG}"
    printf "Secret:        %s\n" "${SECRET:-}"
    printf "EE secret:     %s\n" "$ee"
    printf "URI:           %s\n" "$uri"

    if [[ -n "$stats" ]]; then
      printf '%s\n' "-- live stats --"
      printf "inbound:       %s (active %s)\n" "$s_inbound" "$s_active_in"
      printf "connections:   active %s | outbound %s ready %s | http %s\n" "$s_active" "$s_outbound" "$s_ready_out" "$s_http_conn"
      printf "throughput:    tot_forwarded %s | http_qps %s | qps_get %s\n" "$s_tot_fw" "$s_http_qps" "$s_qps_get"
      printf "workers:       %s\n" "$s_workers"
    else
      printf '%s\n' "-- live stats unavailable --"
    fi
  done
  shopt -u nullglob
}

# ---- main -------------------------------------------------------------------
require_root
cmd="${1:-add}"

case "$cmd" in
  add)
    ensure_deps
    ensure_mtproxy_built
    make_instance
    ;;
  list)
    list_instances
    ;;
  *)
    echo "Usage: $0 [add|list]"
    exit 2
    ;;
esac
