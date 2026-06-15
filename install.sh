#!/bin/bash
# strongMan installer — installs and syncs with your existing strongSwan setup.
# Run as root:  sudo bash install.sh
set -e

# ── configurable defaults ──────────────────────────────────────────────────────
APP_DIR="${STRONGMAN_DIR:-/opt/strongman}"
APP_PORT="${STRONGMAN_PORT:-1515}"
APP_USER="root"
VENV="$APP_DIR/env"
SETTINGS="strongMan.settings.production"
REPO_URL="${STRONGMAN_REPO:-https://github.com/waleedlodhra/strongMan.git}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[strongMan]${NC} $*"; }
ok()    { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
die()   { echo -e "${RED}[ERROR ]${NC} $*" >&2; exit 1; }
step()  { echo ""; echo -e "${CYAN}── $* ──${NC}"; }

# ── root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"

# ── detect best web-accessible IP ─────────────────────────────────────────────
_pick_ip() {
    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
    [[ -n "$iface" ]] && ip -4 addr show dev "$iface" 2>/dev/null \
        | awk '/inet /{gsub(/\/.*/,"",$2); print $2; exit}'
}
SERVER_IP=$(_pick_ip)
[[ -z "$SERVER_IP" ]] && SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "$SERVER_IP" ]] && SERVER_IP="127.0.0.1"

# All non-loopback, non-docker IPs for the final summary
ALL_IPS=$(ip -4 addr 2>/dev/null \
    | awk '/inet /{gsub(/\/.*/,"",$2); print $2}' \
    | grep -v '^127\.' | grep -v '^172\.' | tr '\n' ' ' || echo "$SERVER_IP")

echo ""
echo "================================================="
echo "   strongMan — strongSwan Web GUI Installer"
echo "================================================="
echo ""
info "Install directory : $APP_DIR"
info "Gunicorn port     : $APP_PORT"
info "Primary IP        : $SERVER_IP"
echo ""

# ── 1. prerequisites ──────────────────────────────────────────────────────────
step "Checking prerequisites"

command -v python3 >/dev/null 2>&1 || die "python3 not found — install: apt install python3"
PY_VER=$(python3 -c 'import sys; print(sys.version_info.major*10+sys.version_info.minor)')
[[ $PY_VER -lt 38 ]] && die "Python 3.8+ required (found: $(python3 --version))"

if ! command -v ipsec >/dev/null 2>&1 && ! command -v swanctl >/dev/null 2>&1; then
    die "strongSwan not found — install: apt install strongswan"
fi

if [[ ! -S /var/run/charon.vici ]] && [[ ! -S /run/charon.vici ]]; then
    warn "VICI socket not found — strongSwan (charon) may not be running."
    warn "Start it:  ipsec start   or   systemctl start strongswan"
    warn "Continuing — sync will run once charon is available."
fi
ok "Prerequisites OK"

# ── 2. system packages ────────────────────────────────────────────────────────
step "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-pip python3-venv apache2 git 2>&1 | grep -v '^$' | tail -3
ok "System packages installed"

# ── 3. clone / update ─────────────────────────────────────────────────────────
step "Getting application code"
if [[ -d "$APP_DIR/.git" ]]; then
    info "Updating existing installation at $APP_DIR ..."
    git -C "$APP_DIR" pull --ff-only
    ok "Repository updated"
elif [[ -d "$APP_DIR" ]]; then
    die "$APP_DIR exists but is not a git repo. Remove it or set: STRONGMAN_DIR=/other/path"
else
    info "Cloning to $APP_DIR ..."
    git clone "$REPO_URL" "$APP_DIR"
    ok "Repository cloned"
fi

# ── 4. python virtualenv ──────────────────────────────────────────────────────
step "Setting up Python environment"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -r "$APP_DIR/requirements.txt" -q
ok "Python dependencies installed"

PY="$VENV/bin/python3"
export DJANGO_SETTINGS_MODULE="$SETTINGS"
cd "$APP_DIR"

# ── 5. django database ────────────────────────────────────────────────────────
step "Configuring application"
touch "$APP_DIR/.production"
"$PY" manage.py migrate --run-syncdb -v 0
"$PY" manage.py collectstatic --noinput -v 0 2>/dev/null || true
ok "Database ready"

# ── 6. admin user ─────────────────────────────────────────────────────────────
step "Creating admin account"
ADMIN_USER="${STRONGMAN_ADMIN:-admin}"
ADMIN_PASS="${STRONGMAN_PASS:-}"
if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16 || true)
    [[ -z "$ADMIN_PASS" ]] && ADMIN_PASS="ChangeMe$(date +%s | tail -c 4)"
fi

"$PY" manage.py shell -c "
from django.contrib.auth.models import User
u, created = User.objects.get_or_create(username='${ADMIN_USER}')
u.set_password('${ADMIN_PASS}')
u.is_superuser = True
u.is_staff = True
u.save()
print('Admin account ' + ('created' if created else 'updated') + '.')
" || die "Failed to create admin user — check logs above"

ok "Admin account ready"

# ── 7. gunicorn service ───────────────────────────────────────────────────────
step "Setting up gunicorn service"
mkdir -p /var/log/strongman

cat > /etc/systemd/system/strongman.service << EOF
[Unit]
Description=strongMan — strongSwan Web GUI
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
sleep 2

if systemctl is-active --quiet strongman.service; then
    ok "Gunicorn started"
else
    warn "Gunicorn failed to start — check: journalctl -u strongman -n 30"
fi

# ── 8. apache ─────────────────────────────────────────────────────────────────
step "Configuring Apache reverse proxy"
a2enmod proxy proxy_http 2>/dev/null | grep -v 'already enabled' || true

cat > /etc/apache2/sites-available/strongman.conf << EOF
<VirtualHost *:80>
    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:$APP_PORT/
    ProxyPassReverse / http://127.0.0.1:$APP_PORT/

    ErrorLog  \${APACHE_LOG_DIR}/strongman_error.log
    CustomLog \${APACHE_LOG_DIR}/strongman_access.log combined
</VirtualHost>
EOF

a2ensite strongman 2>/dev/null | grep -v 'already enabled' || true
# Disable default site (try both naming conventions Ubuntu uses)
a2dissite 000-default      2>/dev/null || true
a2dissite 000-default.conf 2>/dev/null || true

systemctl reload apache2
ok "Apache configured"

# ── 9. vici socket permissions ────────────────────────────────────────────────
step "Fixing VICI socket permissions"

cat > /etc/systemd/system/strongman-vici-perm.service << EOF
[Unit]
Description=Fix charon VICI socket group for strongMan

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for s in /var/run/charon.vici /run/charon.vici; do [ -S "\$s" ] && chgrp www-data "\$s" && chmod g+rw "\$s" && echo "Fixed \$s"; done; exit 0'
StartLimitIntervalSec=0
EOF

cat > /etc/systemd/system/strongman-vici-perm.timer << EOF
[Unit]
Description=Keep VICI socket accessible to strongMan (runs every 10s)

[Timer]
OnBootSec=5
OnUnitActiveSec=10
AccuracySec=2

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now strongman-vici-perm.timer 2>/dev/null || true
ok "VICI socket fix active"

# ── 10. sync existing strongswan config ───────────────────────────────────────
step "Syncing existing strongSwan connections"
"$PY" manage.py shell -c "
import sys
try:
    from strongMan.apps.server_connections.sync import auto_sync
    fmt, msgs = auto_sync()
    labels = {'ipsec': 'ipsec.conf', 'swanctl': 'swanctl.conf', 'vici-only': 'VICI live query'}
    print('  Format detected:', labels.get(fmt, fmt))
    for m in msgs:
        print(' ', m)
    print('  Done.')
except Exception as e:
    print('  Sync error:', e)
    print('  Run manually later: python3 $APP_DIR/import_tunnels.py')
" || warn "Sync step had errors — run manually: python3 $APP_DIR/import_tunnels.py"

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
echo "================================================="
echo -e "  ${GREEN}strongMan installed successfully!${NC}"
echo "================================================="
echo ""
echo "  Open the dashboard at:"
for ip in $ALL_IPS; do
    echo -e "    ${GREEN}http://$ip/${NC}"
done
echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║  Username :  $ADMIN_USER"
printf  "  ║  Password :  %-24s║\n" "$ADMIN_PASS"
echo "  ╚══════════════════════════════════════╝"
echo ""
echo -e "  ${YELLOW}SAVE the password above — it will not be shown again.${NC}"
echo ""
echo "  Useful commands:"
echo "    systemctl status strongman           — service status"
echo "    journalctl -u strongman -f           — live logs"
echo "    python3 $APP_DIR/import_tunnels.py   — re-sync strongSwan"
echo "    sudo bash $APP_DIR/uninstall.sh      — remove"
echo ""
