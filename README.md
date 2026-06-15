# strongMan — Enhanced strongSwan Web GUI

A web-based management interface for [strongSwan](https://www.strongswan.org/) IPsec VPN.
This is an enhanced fork of the original [strongswan/strongMan](https://github.com/strongswan/strongMan)
with significant additions for server-side deployments.

## What's new in this fork

| Feature | Original | This fork |
|---|---|---|
| PSK (Pre-Shared Key) connections | ✗ | ✓ |
| Auto-sync from existing ipsec.conf | ✗ | ✓ |
| Write-back to ipsec.conf / ipsec.secrets | ✗ | ✓ |
| Live monitoring dashboard | ✗ | ✓ |
| VICI-based connection discovery | ✗ | ✓ |
| PSK secrets management page | ✗ | ✓ |
| Multi-child SA topology (branch tunnels) | ✗ | ✓ |
| Enhanced SA detail rows (encryption, uptime, rekey timers) | partial | ✓ |
| One-command installer | ✗ | ✓ |

## Requirements

- Ubuntu 20.04+ / Debian 11+ (other distros: manual install)
- strongSwan with the **vici plugin** enabled (`apt install strongswan-plugin-vici`)
- Python 3.8+
- Apache2
- Root / sudo access

## Quick Install

```bash
git clone https://github.com/YOUR_USERNAME/strongMan.git
cd strongMan
sudo bash install.sh
```

The installer will:
1. Install system dependencies (Python3, Apache2)
2. Set up a Python virtualenv with all requirements
3. Configure gunicorn + Apache reverse proxy
4. Fix VICI socket permissions permanently (survives charon restarts)
5. **Auto-sync your existing ipsec.conf** — all your tunnels appear in the GUI immediately
6. Print your admin username and one-time password

## Manual install

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/strongMan.git /opt/strongman
cd /opt/strongman

# 2. Virtualenv
python3 -m venv env
env/bin/pip install -r requirements.txt

# 3. Django setup (touch .production to enable production mode)
touch .production
DJANGO_SETTINGS_MODULE=strongMan.settings.production \
    env/bin/python3 manage.py migrate
DJANGO_SETTINGS_MODULE=strongMan.settings.production \
    env/bin/python3 manage.py createsuperuser

# 4. Sync existing config
python3 import_tunnels.py

# 5. Start gunicorn (see install.sh for the full systemd service)
env/bin/gunicorn --bind 127.0.0.1:1515 strongMan.wsgi:application
```

## Usage

### Server Connections page

- **Toggle** a connection on/off — loads/unloads it from charon via VICI
- **Save & Reload** — saves changes and reloads the live tunnel immediately
- **Sync from /etc/ipsec.conf** button — one-click import of all tunnels
- **Discovered connections** section — tunnels charon knows about but not yet in the GUI, with per-row Import button

### Monitor page

Real-time dashboard, auto-refreshes every 5 seconds:

- Daemon status: version, uptime, worker threads, active SA count
- Per IKE SA: state badge, encryption algorithm, uptime, reauth countdown
- Per child SA: bytes in/out, packet counts, install time, rekey countdown, traffic selectors

### PSK Secrets page

Manage pre-shared keys for all PSK connections in one place.
Saving a PSK updates `/etc/ipsec.secrets` immediately.

### CLI sync

```bash
# Dry-run — preview grouping logic without writing to DB
python3 /opt/strongman/import_tunnels.py --dry-run

# Full sync
python3 /opt/strongman/import_tunnels.py

# Custom paths
python3 /opt/strongman/import_tunnels.py \
    --conf /etc/ipsec.conf \
    --secrets /etc/ipsec.secrets
```

## How write-back works

Every GUI action (create / update / delete / PSK change) automatically rewrites
`/etc/ipsec.conf` and `/etc/ipsec.secrets` atomically. The tunnels stay running until
you click **Save & Reload**, which reloads the config in the live charon process via VICI.

conn blocks in ipsec.conf map 1:1 to child SAs. Multiple `conn` blocks with the
same left/right peer are automatically grouped into a single IKE SA with multiple
children (matching strongSwan's stroke behaviour).

## VICI socket permissions

The installer sets up a systemd timer (`strongman-vici-perm.timer`) that sets
`/var/run/charon.vici` group to `www-data` every 10 seconds. This survives charon
restarts and manual `ipsec restart` calls.

## Updating

```bash
cd /opt/strongman
sudo git pull
sudo env/bin/pip install -r requirements.txt
sudo DJANGO_SETTINGS_MODULE=strongMan.settings.production \
    env/bin/python3 manage.py migrate
sudo systemctl restart strongman
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| GUI can't connect to VICI | `ls -la /var/run/charon.vici` — group must be `www-data`. Run `systemctl start strongman-vici-perm` |
| Connections show DOWN after restart | Click "Sync from ipsec.conf" or run `python3 import_tunnels.py` |
| Login shows 500 error | `journalctl -u strongman -f` to see gunicorn errors |
| ipsec.conf not updated after GUI change | Check gunicorn runs as root; verify `/etc/ipsec.conf` is writable |
| Discovered connections panel shows VICI error | strongSwan charon is not running — start it with `ipsec start` |

## Architecture

```
Browser ──► Apache :80 ──► Gunicorn 127.0.0.1:1515 ──► Django app
                                                            │
                                          ┌─────────────────┤
                                          │                 │
                                   VICI socket      ipsec.conf
                                   /var/run/         /etc/ipsec.conf
                                   charon.vici       /etc/ipsec.secrets
                                          │
                                    strongSwan charon
```

## Uninstall

```bash
sudo bash uninstall.sh
# App files kept at /opt/strongman — remove manually if desired:
# sudo rm -rf /opt/strongman
```

## Original project

This fork is based on [strongswan/strongMan](https://github.com/strongswan/strongMan).
See the original project for client-mode usage, certificate management, and EAP secrets.
