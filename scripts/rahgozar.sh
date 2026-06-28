#!/usr/bin/env bash
set -uo pipefail

INSTALL_DIR="/usr/local/rahgozar"
BIN="$INSTALL_DIR/rahgozar"
DB="$INSTALL_DIR/rahgozar.db"
PORT_FILE="$INSTALL_DIR/port"
SERVICE_FILE="/etc/systemd/system/rahgozar.service"
SELF_PATH="/usr/local/bin/rahgozar"
SERVICE="rahgozar"

REPO="hoseinlolready/RahGozar"
BRANCH="main"
RAW_BASE="${RAHGOZAR_RAW_BASE:-https://raw.githubusercontent.com/$REPO/refs/heads/$BRANCH}"

C_RESET=$'\e[0m'; C_DIM=$'\e[2m'; C_B=$'\e[1m'
C_BLUE=$'\e[38;5;39m'; C_CYAN=$'\e[38;5;43m'; C_GREEN=$'\e[38;5;42m'
C_RED=$'\e[38;5;203m'; C_YEL=$'\e[38;5;215m'; C_GREY=$'\e[38;5;245m'

say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
err()  { printf '%s✗%s %s\n' "$C_RED" "$C_RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YEL" "$C_RESET" "$*"; }
ask()  { local p="$1" v; read -r -p "$(printf '%s? %s%s ' "$C_CYAN" "$C_RESET" "$p")" v; printf '%s' "$v"; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "Run this as root (use sudo)."
    exit 1
  fi
}

arch_bin() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "rahgozar-linux-amd64" ;;
    aarch64|arm64) echo "rahgozar-linux-arm64" ;;
    *) echo "" ;;
  esac
}

# Put the right binary at $BIN. Prefer a local ./dist copy (when the repo is
# unpacked next to the script); otherwise download it from GitHub so the
# curl-pipe-to-bash one-liner works with no local files.
fetch_binary() {
  local b; b="$(arch_bin)"
  if [ -z "$b" ]; then err "Unsupported CPU architecture: $(uname -m)"; return 1; fi

  local sd=""; [ -n "${BASH_SOURCE:-}" ] && [ -f "${BASH_SOURCE:-}" ] && sd="$(cd "$(dirname "${BASH_SOURCE}")" && pwd)"
  local local_src=""
  for cand in "./dist/$b" "./$b" ${sd:+"$sd/dist/$b" "$sd/../dist/$b"}; do
    [ -f "$cand" ] && { local_src="$cand"; break; }
  done

  mkdir -p "$INSTALL_DIR"
  if [ -n "$local_src" ]; then
    install -m 0755 "$local_src" "$BIN"
    ok "Installed binary from $local_src"
  else
    say "Downloading core for $(uname -m) from GitHub..."
    if curl -fL --retry 3 --connect-timeout 15 --progress-bar "$RAW_BASE/dist/$b" -o "$BIN.tmp" && [ -s "$BIN.tmp" ]; then
      chmod +x "$BIN.tmp"; mv "$BIN.tmp" "$BIN"
      ok "Downloaded core from GitHub"
    else
      rm -f "$BIN.tmp"
      err "Could not download the core from $RAW_BASE/dist/$b"
      err "Check the server's internet access to GitHub, or set RAHGOZAR_RAW_BASE to a mirror."
      return 1
    fi
  fi
}

# Install this script as the 'rahgozar' command. Copy the local file if we have
# one, else fetch the script from GitHub (the one-liner case).
install_self() {
  if [ -n "${BASH_SOURCE:-}" ] && [ -f "${BASH_SOURCE:-}" ]; then
    install -m 0755 "${BASH_SOURCE}" "$SELF_PATH" 2>/dev/null && { chmod +x "$SELF_PATH"; return; }
  fi
  curl -fsSL "$RAW_BASE/scripts/rahgozar.sh" -o "$SELF_PATH" 2>/dev/null && chmod +x "$SELF_PATH"
}

pub_ip() {
  local ip=""
  for u in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me"; do
    ip="$(curl -fsS --max-time 4 "$u" 2>/dev/null | tr -d '[:space:]')"
    [ -n "$ip" ] && { echo "$ip"; return; }
  done
  echo "your-server-ip"
}

server_country() {
  local out=""
  out="$(curl -fsS --max-time 4 "https://ipinfo.io/json" 2>/dev/null)" || true
  if [ -n "$out" ]; then
    local country city
    country="$(printf '%s' "$out" | grep -o '"country"[^,]*' | head -1 | cut -d'"' -f4)"
    city="$(printf '%s' "$out" | grep -o '"city"[^,]*' | head -1 | cut -d'"' -f4)"
    if [ -n "$country" ]; then
      [ -n "$city" ] && echo "$city, $country" || echo "$country"
      return
    fi
  fi
  echo "unknown"
}

svc_active()  { systemctl is-active --quiet "$SERVICE" 2>/dev/null; }
svc_enabled() { systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; }
is_installed(){ [ -x "$BIN" ] && [ -f "$SERVICE_FILE" ]; }

get_port() { [ -f "$PORT_FILE" ] && cat "$PORT_FILE" || echo "9090"; }

bin_version() { [ -x "$BIN" ] && "$BIN" -version 2>/dev/null || echo "unknown"; }

header() {
  clear 2>/dev/null || true
  local port ip country status
  port="$(get_port)"; ip="$(pub_ip)"; country="$(server_country)"
  printf '%s' "$C_BLUE"
  cat <<'EOF'
  ╦═╗┌─┐┬ ┬╔═╗┌─┐┌─┐┌─┐┬─┐
  ╠╦╝├─┤├─┤║ ╦│ │┌─┘├─┤├┬┘
  ╩╚═┴ ┴┴ ┴╚═╝└─┘└─┘┴ ┴┴└─
EOF
  printf '%s' "$C_RESET"
  printf '  %stunnel control%s\n\n' "$C_GREY" "$C_RESET"

  if is_installed; then
    if svc_active; then
      printf '  status   %s● running%s\n' "$C_GREEN" "$C_RESET"
    else
      printf '  status   %s● stopped%s\n' "$C_RED" "$C_RESET"
    fi
    printf '  panel    %shttp://%s:%s%s\n' "$C_CYAN" "$ip" "$port" "$C_RESET"
  else
    printf '  status   %snot installed%s\n' "$C_YEL" "$C_RESET"
  fi
  printf '  server   %s (%s)\n' "$country" "$ip"
  printf '  %s────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"
}

write_service() {
  local port="$1"
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=RahGozar tunnel panel
After=network.target

[Service]
Type=simple
ExecStart=$BIN -db $DB -port $port
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

do_install() {
  need_root
  if is_installed; then
    warn "RahGozar is already installed. Use Update to replace the core."
    return
  fi

  local port; port="$(ask 'Panel port [9090]:')"; port="${port:-9090}"

  fetch_binary || return
  echo "$port" > "$PORT_FILE"

  say ""
  say "${C_B}Create the owner account:${C_RESET}"
  "$BIN" -db "$DB" -add-admin || { err "Owner creation failed."; return; }

  write_service "$port"
  systemctl enable --now "$SERVICE" >/dev/null 2>&1

  install_self

  say ""
  if svc_active; then
    ok "Installed and running."
    ok "Panel: ${C_CYAN}http://$(pub_ip):$port${C_RESET}"
    say "${C_GREY}Re-open this menu any time by typing:${C_RESET} ${C_B}rahgozar${C_RESET}"
  else
    err "Installed but the service did not start. Check: journalctl -u $SERVICE -n 50"
  fi
}

do_uninstall() {
  need_root
  if ! is_installed; then warn "RahGozar is not installed."; return; fi
  local c; c="$(ask 'Remove RahGozar? Type yes to confirm:')"
  [ "$c" = "yes" ] || { say "Cancelled."; return; }

  systemctl disable --now "$SERVICE" >/dev/null 2>&1
  rm -f "$SERVICE_FILE"; systemctl daemon-reload

  local keep; keep="$(ask 'Keep the database (accounts + tunnels)? [Y/n]:')"
  if [ "$keep" = "n" ] || [ "$keep" = "N" ]; then
    rm -rf "$INSTALL_DIR"
    ok "Removed everything including the database."
  else
    rm -f "$BIN"
    ok "Removed. Database kept at $DB"
  fi
  rm -f "$SELF_PATH"
}

do_update() {
  need_root
  if ! is_installed; then warn "Not installed yet — use Install."; return; fi
  local before; before="$(bin_version)"
  say "Current version: ${C_B}${before}${C_RESET}"
  say "Stopping service..."
  systemctl stop "$SERVICE" >/dev/null 2>&1
  if fetch_binary; then
    install_self
    local after; after="$(bin_version)"
    say "Starting service..."
    systemctl start "$SERVICE" >/dev/null 2>&1
    sleep 1
    if svc_active; then
      ok "Updated: ${C_B}${before}${C_RESET} → ${C_B}${after}${C_RESET}"
      ok "Panel: ${C_CYAN}http://$(pub_ip):$(get_port)${C_RESET}"
    else
      err "Updated to ${after} but the service did not start. Check: journalctl -u $SERVICE -n 50"
    fi
  else
    say "Restoring previous core..."
    systemctl start "$SERVICE" >/dev/null 2>&1
    err "Update failed; kept the existing core (${before})."
  fi
}

do_add_admin()  { need_root; is_installed && "$BIN" -db "$DB" -add-admin || warn "Not installed."; }
do_del_admin()  {
  need_root; is_installed || { warn "Not installed."; return; }
  "$BIN" -db "$DB" -list-admins
  local u; u="$(ask 'Username to delete:')"
  [ -n "$u" ] && "$BIN" -db "$DB" -del-admin "$u"
}
do_list_admins(){ need_root; is_installed && "$BIN" -db "$DB" -list-admins || warn "Not installed."; }

do_restart() {
  need_root
  say "Restarting ${SERVICE}..."
  if systemctl restart "$SERVICE"; then
    sleep 1
    if svc_active; then
      ok "Restarted — running ${C_B}$(bin_version)${C_RESET}"
      ok "Panel: ${C_CYAN}http://$(pub_ip):$(get_port)${C_RESET}"
    else
      err "Restarted but the service is not active. Check: journalctl -u $SERVICE -n 50"
    fi
  else
    err "Restart failed."
  fi
}
do_start()   { need_root; systemctl start "$SERVICE" && ok "Started." || err "Start failed."; }
do_stop()    { need_root; systemctl stop "$SERVICE" && ok "Stopped." || err "Stop failed."; }

do_status() {
  systemctl status "$SERVICE" --no-pager -l 2>&1 | head -20 || warn "No service."
}

do_logs() {
  say "${C_GREY}Showing live logs — press Ctrl-C to return.${C_RESET}"
  journalctl -u "$SERVICE" -n 60 -f 2>/dev/null || warn "No logs available."
}

do_debugging() {
  need_root
  if ! is_installed; then warn "Not installed."; return; fi
  case "${1:-}" in
    true|on|1)  "$BIN" -db "$DB" -debug on  && ok "Debug logging ON. Watch it with: rahgozar logs" ;;
    false|off|0) "$BIN" -db "$DB" -debug off && ok "Debug logging OFF." ;;
    *) say "usage: rahgozar debugging true|false" ;;
  esac
}

pause() { read -r -p "$(printf '\n%spress enter to continue%s' "$C_DIM" "$C_RESET")" _; }

menu() {
  while true; do
    header
    cat <<EOF
  ${C_B}1${C_RESET}  Install
  ${C_B}2${C_RESET}  Uninstall
  ${C_B}3${C_RESET}  Update
  ${C_B}4${C_RESET}  Add admin
  ${C_B}5${C_RESET}  Delete admin
  ${C_B}6${C_RESET}  List admins
  ${C_B}7${C_RESET}  Restart
  ${C_B}8${C_RESET}  Start / Stop
  ${C_B}9${C_RESET}  Status
  ${C_B}10${C_RESET} Logs
  ${C_B}0${C_RESET}  Exit
EOF
    local ch; ch="$(ask 'choose:')"
    case "$ch" in
      1) do_install; pause ;;
      2) do_uninstall; pause ;;
      3) do_update; pause ;;
      4) do_add_admin; pause ;;
      5) do_del_admin; pause ;;
      6) do_list_admins; pause ;;
      7) do_restart; pause ;;
      8)
         if svc_active; then do_stop; else do_start; fi; pause ;;
      9) do_status; pause ;;
      10) do_logs ;;
      0|q|Q) exit 0 ;;
      *) warn "Unknown choice." ; sleep 1 ;;
    esac
  done
}

# Allow direct subcommands too: rahgozar install|status|restart|logs|...
# Works locally (`rahgozar update`) and over the one-liner without the menu:
#   curl -sL <url>/scripts/rahgozar.sh | sudo bash -s -- update
#   sudo RAHGOZAR_CMD=update bash -c "$(curl -sL <url>/scripts/rahgozar.sh)"
case "${1:-${RAHGOZAR_CMD:-}}" in
  install)   do_install ;;
  uninstall) do_uninstall ;;
  update)    do_update ;;
  restart)   do_restart ;;
  start)     do_start ;;
  stop)      do_stop ;;
  status)    do_status ;;
  logs)      do_logs ;;
  add-admin) do_add_admin ;;
  del-admin) do_del_admin ;;
  debugging) do_debugging "${2:-}" ;;
  ""|menu)   menu ;;
  *) say "usage: rahgozar [install|uninstall|update|restart|start|stop|status|logs|add-admin|del-admin]" ;;
esac
