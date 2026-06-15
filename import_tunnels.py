#!/usr/bin/env python3
"""
CLI wrapper: sync existing strongSwan config into StrongMan's DB.

Supports all strongSwan config formats:
  ipsec.conf    (legacy stroke)
  swanctl.conf  (modern swanctl)
  VICI-only     (fallback: queries charon directly)

Usage:
    python3 import_tunnels.py [--dry-run]
    python3 import_tunnels.py --conf /etc/ipsec.conf --secrets /etc/ipsec.secrets
    python3 import_tunnels.py --swanctl /etc/swanctl/swanctl.conf
    python3 import_tunnels.py --vici     # force VICI-only import
"""
import os
import sys
import argparse

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_settings = ('strongMan.settings.production'
             if os.path.exists(os.path.join(_HERE, '.production'))
             else 'strongMan.settings.local')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', _settings)

import django
django.setup()

from strongMan.apps.server_connections.sync import (
    detect_config_format, auto_sync,
    sync_from_conf, sync_from_swanctl, sync_from_vici,
    get_discovered_connections, find_vici_socket,
    parse_ipsec_conf, parse_ipsec_secrets, parse_swanctl_conf,
    _ike_group_key,
)


def main():
    parser = argparse.ArgumentParser(
        description="Sync strongSwan config into StrongMan DB (auto-detects format)")
    parser.add_argument('--conf',    help='Path to ipsec.conf (forces ipsec format)')
    parser.add_argument('--secrets', default='/etc/ipsec.secrets')
    parser.add_argument('--swanctl', help='Path to swanctl.conf (forces swanctl format)', dest='swanctl_path')
    parser.add_argument('--vici',    action='store_true', help='Force VICI-only import')
    parser.add_argument('--dry-run', action='store_true', help='Parse only, no DB writes')
    args = parser.parse_args()

    print(f"VICI socket: {find_vici_socket()}")

    if args.dry_run:
        fmt = detect_config_format()
        print(f"Detected format: {fmt}")
        if args.conf:
            conns = parse_ipsec_conf(args.conf)
            psks  = parse_ipsec_secrets(args.secrets)
            print(f"\nParsed {len(conns)} conn block(s) from {args.conf}, {len(psks)} PSK(s)")
            for c in conns:
                print(f"  [{c['_name']}] {c.get('left','')}→{c.get('right','')} "
                      f"auth={c.get('authby','?')} ke={c.get('keyexchange','?')}")
        elif args.swanctl_path:
            conns, psks = parse_swanctl_conf([args.swanctl_path])
            print(f"\nParsed {len(conns)} child SA(s) from swanctl, {len(psks)} PSK(s)")
            for c in conns:
                print(f"  [{c['_name']}] {c.get('left','')}→{c.get('right','')}")
        else:
            if fmt == 'ipsec':
                conns = parse_ipsec_conf()
                psks  = parse_ipsec_secrets()
                print(f"\nParsed {len(conns)} conn block(s), {len(psks)} PSK(s)")
                groups = {}
                for c in conns:
                    k = _ike_group_key(c)
                    groups.setdefault(k, []).append(c)
                for k, g in groups.items():
                    primary = g[0]
                    children = [c['_name'] for c in g[1:]]
                    extra = f" +[{', '.join(children)}]" if children else ""
                    print(f"  [{primary['_name']}]{extra} {k[0]}→{k[1]}")
            elif fmt == 'swanctl':
                conns, psks = parse_swanctl_conf()
                print(f"\nParsed {len(conns)} child SA(s) from swanctl, {len(psks)} PSK(s)")
                for c in conns:
                    print(f"  [{c['_name']}] {c.get('left','')}→{c.get('right','')}")
            else:
                print(f"\nNo config files found — would do VICI-only import")
        print("\n(dry-run: no DB changes)")
        return

    # Live sync
    print("\nSyncing:")
    if args.vici:
        results = sync_from_vici()
        fmt = 'vici-only'
    elif args.conf:
        results = sync_from_conf(args.conf, args.secrets)
        fmt = 'ipsec'
    elif args.swanctl_path:
        results = sync_from_swanctl([args.swanctl_path])
        fmt = 'swanctl'
    else:
        fmt, results = auto_sync()

    fmt_labels = {'ipsec': 'ipsec.conf', 'swanctl': 'swanctl.conf', 'vici-only': 'VICI'}
    print(f"  Format: {fmt_labels.get(fmt, fmt)}")
    for msg in results:
        print(f"  {msg}")

    print("\nVICI discovery check:")
    discovered, err = get_discovered_connections()
    if err:
        print(f"  VICI error: {err}")
    elif discovered:
        print(f"  {len(discovered)} in charon but not in DB:")
        for d in discovered:
            print(f"    - {d['name']} ({d['version']}, {d['auth_class']})")
    else:
        print("  All charon connections are in the DB.")
    print("\nDone.")


if __name__ == '__main__':
    main()
