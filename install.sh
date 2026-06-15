#!/bin/bash
# strongMan installer
# Installs strongMan and syncs your existing strongSwan config into the GUI.
# Run as root: sudo bash install.sh
set -euo pipefail

# ── configurable defaults ──────────────────────────────────────────────────────
APP_DIR="${STRONGMAN_DIR:-/opt/strongman}"
APP_PORT="${STRONGMAN_PORT:-1515}"
APP_USER="root"          # needs root for /etc/ipsec.conf write-back
VENV="$APP_DIR/env"
SETTINGS="strongMan.settings.production"
REPO_URL="${STRONGMAN_REPO:-https://github.com/waleedlodhra/strongMan.git}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[strongMan]${NC} $*"; }
ok()    { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
die()   { echo -e "${RED}[ERROR ]${NC} $*" >&2; exit 1; }

# ── root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"

# ── detect best web-accessible IP ─────────────────────────────────────────────
# Prefer the IP used for the default route (internet-facing), skip loopback/docker
_pick_ip() {
    # 1. IP of the default-route interface
    local gw_if
    gw_if=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    if [[ -n "$gw_if" ]]; then
        ip -4 addr show dev "$gw_if" 2>/dev/null \
            | awk '/inet / {gsub(/\/.*/, "", $2); print $2; exit}'
    fi
}
SERVER_IP=$(_pick_ip)
[[ -z "$SERVER_IP" ]] && SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "$SERVER_IP" ]] && SERVER_IP="127.0.0.1"

# Collect ALL IPs for display (excluding loopback and docker ranges)
ALL_IPS=$(ip -4 addr 2>/dev/null \
    | awk '/inet / {gsub(/\/.*/, "", $2); print $2}' \
    | grep -v '^127\.' | grep -v '^172\.' | tr '\n' ' ')

echo ""
echo "================================================="
echo "   strongMan — strongSwan Web GUI Installer"
echo "================================================="
echo ""
info "Install directory : $APP_DIR"
info "Gunicorn port     : $APP_PORT"
info "Primary IP        : $SERVER_IP"
echo ""

# ── 1. prerequisite checks ────────────────────────────────────────────────────
info "Checking prerequisites..."

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install it: apt install python3"
PY_VER=$(python3 -c 'import sys; print(sys.version_info.major*10+sys.version_info.minor)')
[[ $PY_VER -lt 38 ]] && die "Python 3.8+ required (found $(python3 --version))"

if ! command -v ipsec >/dev/null 2>&1 && ! command -v swanctl >/dev/null 2>&1; then
    die "strongSwan not found. Install it first: apt install strongswan"
fi

if [[ ! -S /var/run/charon.vici ]] && [[ ! -S /run/charon.vici ]]; then
    warn "VICI socket not found — is strongSwan (charon) running?"
    warn "Start it with: ipsec start   OR   systemctl start strongswan"
    warn "Continuing anyway — sync will run automatically once charon is up."
fi

ok "Prerequisites OK"

# ── 2. install system packages ────────────────────────────────────────────────
info "Installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-pip python3-venv apache2 git >/dev/null
ok "System packages installed"

# ── 3. clone / update repo ────────────────────────────────────────────────────
if [[ -d "$APP_DIR/.git" ]]; then
    info "Updating existing installation at $APP_DIR..."
    git -C "$APP_DIR" pull --ff-only
    ok "Repository updated"
elif [[ -d "$APP_DIR" ]]; then
    die "$APP_DIR exists but is not a git repo. Remove it or set STRONGMAN_DIR=/other/path"
else
    info "Cloning repository to $APP_DIR..."
    git clone "$REPO_URL" "$APP_DIR"
    ok "Repository cloned"
fi

# ── 4. virtualenv + dependencies ──────────────────────────────────────────────
info "Setting up Python virtual environment..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -r "$APP_DIR/requirements.txt" -q
ok "Python dependencies installed"

# ── 5. Django setup ───────────────────────────────────────────────────────────
info "Configuring Django..."
touch "$APP_DIR/.production"

PY="$VENV/bin/python3"
export DJANGO_SETTINGS_MODULE="$SETTINGS"

cd "$APP_DIR"
"$PY" manage.py migrate --run-syncdb -v 0
"$PY" manage.py collectstatic --noinput -v 0 2>/dev/null || true
ok "Database migrated"

# ── 6. create admin user ──────────────────────────────────────────────────────
info "Creating admin user..."
ADMIN_USER="${STRONGMAN_ADMIN:-admin}"
ADMIN_PASS="${STRONGMAN_PASS:-}"
if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
fi

# Write a temp script so sys.path and django.setup() are reliable
TMPSCRIPT=$(mktemp /tmp/strongman_setup_XXXXXX.py)
cat > "$TMPSCRIPT" << PYEOF
import sys, os
sys.path.insert(0, '$APP_DIR')
os.environ['DJANGO_SETTINGS_MODULE'] = '$SETTINGS'
import django
django.setup()
from django.contrib.auth.models import User
username = '$ADMIN_USER'
password = '$ADMIN_PASS'
if User.objects.filter(username=username).exists():
    u = User.objects.get(username=username)
    u.set_password(password)
    u.save()
    print('updated')
else:
    User.objects.create_superuser(username, '', password)
    print('created')
PYEOF

"$PY" "$TMPSCRIPT"
rm -f "$TMPSCRIPT"
ok "Admin user ready"

# ── 7. gunicorn systemd service ───────────────────────────────────────────────
info "Creating gunicorn service..."
mkdir -p /var/log/strongman

cat > /etc/systemd/system/strongman.service << EOF
[Unit]
Description=strongMan Django/Gunicorn service
After=network.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$APP_DIR
Environment=DJANGO_SETTINGS_MODULE=$SETTINGS
Environment=STRONGMAN_ALLOWED_HOSTS=*
ExecStart=$VENV/bin/gunicorn \\
    --workers 4 \\
    --bind 127.0.0.1:$APP_PORT \\
    --timeout 60 \\
    --log-level info \\
    --access-logfile /var/log/strongman/access.log \\
    --error-logfile  /var/log/strongman/error.log \\
    strongMan.wsgi:application
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable strongman.service
systemctl restart strongman.service
ok "Gunicorn service started"

# ── 8. Apache reverse proxy ───────────────────────────────────────────────────
info "Configuring Apache..."
a2enmod proxy proxy_http -q 2>/dev/null || true

cat > /etc/apache2/sites-available/strongman.conf << EOF
<VirtualHost *:80>
    # Accessible on all interfaces — open http://YOUR_SERVER_IP/
    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:$APP_PORT/
    ProxyPassReverse / http://127.0.0.1:$APP_PORT/

    ErrorLog  \${APACHE_LOG_DIR}/strongman_error.log
    CustomLog \${APACHE_LOG_DIR}/strongman_access.log combined
</VirtualHost>
EOF

a2ensite strongman.conf -q 2>/dev/null || true
a2dissite 000-default.conf -q 2>/dev/null || true
systemctl reload apache2
ok "Apache configured (listening on all interfaces, port 80)"

# ── 9. VICI socket permission fix ─────────────────────────────────────────────
info "Setting up VICI socket permission fix..."

cat > /etc/systemd/system/strongman-vici-perm.service << EOF
[Unit]
Description=Ensure charon VICI socket is accessible by strongMan

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for s in /var/run/charon.vici /run/charon.vici; do [ -S "\$s" ] && chgrp www-data "\$s" && chmod g+rw "\$s"; done; true'
StartLimitIntervalSec=0
EOF

cat > /etc/systemd/system/strongman-vici-perm.timer << EOF
[Unit]
Description=Keep charon VICI socket accessible to strongMan

[Timer]
OnBootSec=5
OnUnitActiveSec=10
AccuracySec=2

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now strongman-vici-perm.timer
ok "VICI socket permission fix enabled"

# ── 10. sync existing strongSwan config ───────────────────────────────────────
info "Syncing existing strongSwan config..."
SYNCSCRIPT=$(mktemp /tmp/strongman_sync_XXXXXX.py)
cat > "$SYNCSCRIPT" << PYEOF
import sys, os
sys.path.insert(0, '$APP_DIR')
os.environ['DJANGO_SETTINGS_MODULE'] = '$SETTINGS'
import django
django.setup()
from strongMan.apps.server_connections.sync import auto_sync
fmt, msgs = auto_sync()
fmt_labels = {'ipsec': 'ipsec.conf', 'swanctl': 'swanctl.conf', 'vici-only': 'VICI live query'}
print(f"  Format detected: {fmt_labels.get(fmt, fmt)}")
for m in msgs:
    print(f"  {m}")
PYEOF

"$PY" "$SYNCSCRIPT" && ok "strongSwan config synced" || warn "Sync failed — run manually: python3 $APP_DIR/import_tunnels.py"
rm -f "$SYNCSCRIPT"

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo "================================================="
echo -e "  ${GREEN}strongMan installed successfully!${NC}"
echo "================================================="
echo ""
echo "  Access the dashboard on any of these addresses:"
for ip in $ALL_IPS; do
    echo "    http://$ip/"
done
echo ""
echo "  ┌─────────────────────────────────────┐"
echo "  │  Username : $ADMIN_USER"
echo "  │  Password : $ADMIN_PASS"
echo "  └─────────────────────────────────────┘"
echo ""
echo "  SAVE the password above — it will not be shown again."
echo ""
echo "  Useful commands:"
echo "    systemctl status strongman          # gunicorn status"
echo "    journalctl -u strongman -f          # live logs"
echo "    python3 $APP_DIR/import_tunnels.py  # re-sync strongSwan config"
echo "    sudo bash $APP_DIR/uninstall.sh     # remove"
echo ""
