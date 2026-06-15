#!/usr/bin/env python3
"""
CLI wrapper: sync /etc/ipsec.conf + /etc/ipsec.secrets into StrongMan's DB.

Usage:
    python3 import_tunnels.py [--dry-run] [--conf /etc/ipsec.conf] [--secrets /etc/ipsec.secrets]

The actual sync logic lives in strongMan/apps/server_connections/sync.py
so the web UI and this CLI share the same code path.
"""
import os
import sys
import argparse

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
_settings = 'strongMan.settings.production' if os.path.exists(os.path.join(_HERE, '.production')) else 'strongMan.settings.local'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', _settings)

import django
django.setup()

from strongMan.apps.server_connections.sync import (
    parse_ipsec_conf, parse_ipsec_secrets, _ike_group_key,
    sync_from_conf, get_discovered_connections,
)


def main():
    parser = argparse.ArgumentParser(description="Sync ipsec.conf into StrongMan DB")
    parser.add_argument('--conf',    default='/etc/ipsec.conf')
    parser.add_argument('--secrets', default='/etc/ipsec.secrets')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()

    print(f"Reading {args.conf} ...")
    try:
        conns = parse_ipsec_conf(args.conf)
    except FileNotFoundError:
        print(f"  Error: {args.conf} not found")
        sys.exit(1)
    print(f"  found {len(conns)} connection(s)")

    print(f"\nReading {args.secrets} ...")
    psks = parse_ipsec_secrets(args.secrets)
    print(f"  found {len(psks)} PSK entry(ies)")

    if args.dry_run:
        print("\nDry-run — IKE grouping preview:")
        groups = {}
        order = []
        for conf in conns:
            key = _ike_group_key(conf)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(conf)
        for key in order:
            group = groups[key]
            authby = group[0].get('authby', 'pubkey')
            left = group[0].get('left', '')
            right = group[0].get('right', '')
            primary = group[0]['_name']
            children = [c['_name'] for c in group[1:]]
            suffix = f" + children: {children}" if children else ""
            print(f"  [{primary}] {left}→{right} auth={authby}{suffix}")
    else:
        print("\nSyncing:")
        results = sync_from_conf(args.conf, args.secrets)
        for msg in results:
            print(f"  {msg}")

        print("\nVICI discovery check:")
        discovered, err = get_discovered_connections()
        if err:
            print(f"  VICI error: {err}")
        elif discovered:
            print(f"  {len(discovered)} connection(s) in charon but not yet in DB:")
            for d in discovered:
                print(f"    - {d['name']} ({d['version']}, {d['auth_class']})")
        else:
            print("  All charon connections are in the DB.")

    print("\nDone.")


if __name__ == '__main__':
    main()
