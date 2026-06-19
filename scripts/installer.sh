#!/usr/bin/env bash
# RahGozar installer
set -euo pipefail

REPO="hoseinlolready/RahGozar"
BRANCH="main"
INSTALL_DIR="/opt/rahgozar"
BIN="$INSTALL_DIR/rahgozar"
DB="$INSTALL_DIR/rahgozar.db"
SERVICE="/etc/systemd/system/rahgozar.service"
PORT="${RAHGOZAR_PORT:-9090}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (use sudo)." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

ASSET="rahgozar-linux-${ARCH}"
URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/dist/${ASSET}"

echo "Installing RahGozar (${ARCH}) into ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"

echo "Downloading ${ASSET}..."
if ! curl -fSL "$URL" -o "$BIN"; then
  echo "Download failed. Check the release URL or your network." >&2
  exit 1
fi
chmod +x "$BIN"

cat > /usr/local/bin/rahgozar <<EOF
#!/usr/bin/env bash
# RahGozar admin CLI.
DB="$DB"
BIN="$BIN"
case "\${1:-}" in
  add-admin)   "\$BIN" -db "\$DB" -add-admin ;;
  list-admins) "\$BIN" -db "\$DB" -list-admins ;;
  del-admin)   "\$BIN" -db "\$DB" -del-admin "\${2:?usage: rahgozar del-admin <username>}" ;;
  restart)     systemctl restart rahgozar; echo "restarted" ;;
  status)      systemctl status rahgozar --no-pager ;;
  logs)        journalctl -u rahgozar -f ;;
  *)
    echo "RahGozar CLI"
    echo "  rahgozar add-admin            create an admin / owner account"
    echo "  rahgozar list-admins          list accounts"
    echo "  rahgozar del-admin <user>     delete an admin and their tunnels"
    echo "  rahgozar restart|status|logs  manage the service"
    ;;
esac
EOF
chmod +x /usr/local/bin/rahgozar

if [[ ! -f "$DB" ]]; then
  echo
  echo "No database found - let's create the owner account now."
  "$BIN" -db "$DB" -add-admin
fi

echo "Writing systemd service..."
cat > "$SERVICE" <<EOF
[Unit]
Description=RahGozar Tunnel Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$BIN -db $DB -port $PORT
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rahgozar >/dev/null 2>&1 || true
systemctl restart rahgozar

IP="$(curl -s --max-time 3 https://api.ipify.org || echo "<server-ip>")"
echo
echo "RahGozar is installed and running."
echo "  Panel:    http://${IP}:${PORT}"
echo "  Manage:   rahgozar add-admin | list-admins | del-admin | status | logs"
echo "  Service:  systemctl {start,stop,restart,status} rahgozar"
