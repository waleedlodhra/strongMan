#!/bin/bash
# strongMan uninstaller — removes services and Apache config.
# The app directory and database are NOT deleted (to preserve config).
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash uninstall.sh"; exit 1; }

APP_DIR="${STRONGMAN_DIR:-/opt/strongman}"

echo "Removing strongMan services..."

systemctl stop  strongman.service           2>/dev/null || true
systemctl disable strongman.service         2>/dev/null || true
rm -f /etc/systemd/system/strongman.service

systemctl stop  strongman-vici-perm.timer   2>/dev/null || true
systemctl stop  strongman-vici-perm.service 2>/dev/null || true
systemctl disable strongman-vici-perm.timer 2>/dev/null || true
rm -f /etc/systemd/system/strongman-vici-perm.service
rm -f /etc/systemd/system/strongman-vici-perm.timer

a2dissite strongman.conf                    2>/dev/null || true
rm -f /etc/apache2/sites-available/strongman.conf
systemctl reload apache2                    2>/dev/null || true

systemctl daemon-reload

echo ""
echo "strongMan services removed."
echo "App directory NOT deleted: $APP_DIR"
echo "To fully remove: rm -rf $APP_DIR"
echo ""
