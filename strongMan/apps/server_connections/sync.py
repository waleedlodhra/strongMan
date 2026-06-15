"""
Shared sync logic: parse ipsec.conf + ipsec.secrets → upsert DB records.
Also provides VICI-based discovery helpers.
Usable from both the Django web layer and the CLI import_tunnels.py script.
"""
import re

from strongMan.apps.server_connections.models.connections import Connection, IKEv2PSK
from strongMan.apps.server_connections.models.specific import Child, Address, Proposal
from strongMan.apps.server_connections.models.authentication import Authentication, PskAuthentication
from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper


# ─── ipsec.conf parser ────────────────────────────────────────────────────────

def parse_ipsec_conf(path='/etc/ipsec.conf'):
    connections = []
    current = None
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('conn '):
                name = line.split(None, 1)[1].strip()
                if name == '%default':
                    current = None
                else:
                    current = {'_name': name}
                    connections.append(current)
                continue
            if current is not None and '=' in line:
                key, _, val = line.partition('=')
                current[key.strip()] = val.strip()
    return connections


def parse_ipsec_secrets(path='/etc/ipsec.secrets'):
    psks = {}
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if ': PSK ' not in line and ': psk ' not in line.lower():
                    continue
                parts = re.split(r'\s*:\s*(?:PSK|psk)\s+', line, maxsplit=1)
                if len(parts) != 2:
                    continue
                ids = parts[0].strip().split()
                secret = parts[1].strip().strip('"').strip("'")
                if len(ids) >= 2:
                    key = (ids[0], ids[1])
                elif len(ids) == 1:
                    key = (ids[0], '%any')
                else:
                    key = ('%any', '%any')
                psks.setdefault(key, secret)
    except FileNotFoundError:
        pass
    return psks


def lookup_psk(psks, left, right):
    for key in [(left, right), (right, left), (left, '%any'), ('%any', right), ('%any', '%any')]:
        if key in psks:
            return psks[key]
    return ''


def _detect_version(conf):
    ke = conf.get('keyexchange', 'ikev2').lower()
    return '1' if ke in ('ikev1', 'ike') else '2'


def _normalise_proposal(raw):
    return raw.rstrip('!') if raw else None


# ─── DB upsert ────────────────────────────────────────────────────────────────

def _ike_group_key(conf):
    """Key that identifies a unique IKE SA: same peer pair + IKE params = same SA."""
    return (
        conf.get('left', ''),
        conf.get('right', ''),
        conf.get('keyexchange', 'ikev2').lower(),
        conf.get('authby', 'pubkey').lower(),
        conf.get('ike', ''),
    )


def upsert_connection_group(primary_conf, child_confs, psks):
    """
    Create/update ONE DB Connection for a group of ipsec.conf blocks that share
    the same IKE SA (same left/right/auth/ike params). Each conf block becomes
    a separate Child SA.
    Returns (conn, created, message).
    """
    name = primary_conf['_name']
    authby = primary_conf.get('authby', 'pubkey').lower()

    if authby not in ('secret', 'psk'):
        skipped = [c['_name'] for c in [primary_conf] + child_confs]
        return None, False, f"{', '.join(skipped)}: skipped (auth={authby} — needs certificate)"

    left = primary_conf.get('left', '')
    right = primary_conf.get('right', '')
    version = _detect_version(primary_conf)
    ike_prop = _normalise_proposal(primary_conf.get('ike', ''))
    auto = primary_conf.get('auto', 'ignore')
    initiate = auto in ('start', 'route')
    psk_value = lookup_psk(psks, left, right)

    existing = Connection.objects.filter(profile=name).first()
    created = existing is None

    if existing:
        conn = existing.subclass()
        conn.version = version
        conn.initiate = initiate
        conn.save()
    else:
        conn = IKEv2PSK.objects.create(
            profile=name,
            version=version,
            connection_type='site_to_site',
            initiate=initiate,
            enabled=True,
            send_certreq=False,
        )

    conn.server_local_addresses.all().delete()
    conn.server_remote_addresses.all().delete()
    Address.objects.create(value=left, local_addresses=conn)
    Address.objects.create(value=right, remote_addresses=conn)

    conn.server_proposals.all().delete()
    if ike_prop:
        Proposal.objects.create(type=ike_prop, connection=conn)

    Authentication.objects.filter(local=conn).delete()
    Authentication.objects.filter(remote=conn).delete()
    PskAuthentication.objects.create(
        name='local-1', auth='psk', round=1, local=conn,
        psk=psk_value, identity=left,
    )
    PskAuthentication.objects.create(
        name='remote-1', auth='psk', round=1, remote=conn,
        psk='', identity=right,
    )

    # Rebuild all child SAs from every conf block in this group
    conn.server_children.all().delete()
    all_confs = [primary_conf] + child_confs
    for conf in all_confs:
        left_subnets = [s.strip() for s in conf.get('leftsubnet', '').split(',') if s.strip()]
        right_subnets = [s.strip() for s in conf.get('rightsubnet', '').split(',') if s.strip()]
        esp_prop = _normalise_proposal(conf.get('esp', ''))
        child = Child.objects.create(
            name=conf['_name'], mode='tunnel', start_action='start', connection=conn,
        )
        for ts in left_subnets:
            Address.objects.create(value=ts, local_ts=child)
        for ts in right_subnets:
            Address.objects.create(value=ts, remote_ts=child)
        if esp_prop:
            Proposal.objects.create(type=esp_prop, child=child)

    child_names = [c['_name'] for c in all_confs]
    verb = 'created' if created else 'updated'
    extra = f" (+children: {', '.join(child_names[1:])})" if len(child_names) > 1 else ""
    return conn, created, f"{name}: {verb}{extra}"


# Keep single-block form for backward-compat with import_tunnels.py
def upsert_connection(conf, psks):
    return upsert_connection_group(conf, [], psks)


def sync_from_conf(conf_path='/etc/ipsec.conf', secrets_path='/etc/ipsec.secrets'):
    """
    Full sync: parse ipsec.conf + ipsec.secrets, upsert all PSK connections.
    Conn blocks sharing the same IKE SA (same left/right/auth) are merged into
    one DB Connection with multiple Child SAs.
    Returns list of result message strings.
    """
    try:
        conns = parse_ipsec_conf(conf_path)
    except FileNotFoundError:
        return [f"Error: {conf_path} not found"]

    psks = parse_ipsec_secrets(secrets_path)

    # Group conn blocks that share the same IKE SA parameters
    groups = {}   # group_key -> [conf, ...]
    order = []    # preserve order of first appearance
    for conf in conns:
        key = _ike_group_key(conf)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(conf)

    # Track which profiles are the primary (IKE connection) names after grouping
    primary_profiles = set()
    child_profiles = set()   # secondary conn names that get merged into a parent
    for key in order:
        group = groups[key]
        primary_profiles.add(group[0]['_name'])
        for c in group[1:]:
            child_profiles.add(c['_name'])

    # Remove any DB connections whose profile matches a secondary name from a
    # previous un-grouped sync run (they are now merged into the primary)
    removed = []
    for profile in child_profiles:
        stale = Connection.objects.filter(profile=profile).first()
        if stale:
            stale.delete()
            removed.append(profile)

    messages = []
    if removed:
        messages.append(f"Removed stale standalone entries: {', '.join(removed)}")

    for key in order:
        group = groups[key]
        _, _, msg = upsert_connection_group(group[0], group[1:], psks)
        messages.append(msg)

    return messages


# ─── VICI discovery ───────────────────────────────────────────────────────────

def _decode(val):
    if isinstance(val, (bytes, bytearray)):
        return val.decode('utf-8', errors='replace')
    return str(val)


def get_vici_conn_details(name, raw):
    """Parse a raw VICI list_conns entry into a clean dict."""
    version = _decode(raw.get(b'version', raw.get('version', b'?')))
    local_addrs = [_decode(a) for a in raw.get(b'local_addrs', raw.get('local_addrs', []))]
    remote_addrs = [_decode(a) for a in raw.get(b'remote_addrs', raw.get('remote_addrs', []))]

    auth_class = 'unknown'
    for key in list(raw.keys()):
        key_str = _decode(key) if isinstance(key, bytes) else key
        if key_str.startswith('local-'):
            sub = raw[key]
            cls_val = sub.get(b'class', sub.get('class', b''))
            auth_class = _decode(cls_val)
            break

    children = {}
    raw_children = raw.get(b'children', raw.get('children', {}))
    for cname, cdetails in raw_children.items():
        cname_str = _decode(cname)
        lts = [_decode(a) for a in cdetails.get(b'local-ts', cdetails.get('local-ts', []))]
        rts = [_decode(a) for a in cdetails.get(b'remote-ts', cdetails.get('remote-ts', []))]
        children[cname_str] = {'local_ts': lts, 'remote_ts': rts}

    return {
        'name': name,
        'version': version,
        'auth_class': auth_class,
        'local_addrs': ', '.join(local_addrs),
        'remote_addrs': ', '.join(remote_addrs),
        'children': children,
    }


def get_discovered_connections():
    """
    Return list of connections charon knows about but are not yet in the DB.
    """
    try:
        v = ViciWrapper()
        db_profiles = set(Connection.objects.values_list('profile', flat=True))
        discovered = []
        for conn in v.session.list_conns():
            for name, details in conn.items():
                name_str = _decode(name) if isinstance(name, bytes) else name
                if name_str not in db_profiles:
                    discovered.append(get_vici_conn_details(name_str, details))
        return discovered, None
    except Exception as e:
        return [], str(e)


def import_from_vici(conn_name):
    """
    Import a single connection from VICI into the DB (PSK value left blank).
    Returns (conn, message).
    """
    try:
        v = ViciWrapper()
        raw_list = {}
        for conn in v.session.list_conns():
            for name, details in conn.items():
                name_str = _decode(name) if isinstance(name, bytes) else name
                raw_list[name_str] = details

        if conn_name not in raw_list:
            return None, f"Connection '{conn_name}' not found in VICI"

        raw = raw_list[conn_name]
        info = get_vici_conn_details(conn_name, raw)

        local_addrs = [a.strip() for a in info['local_addrs'].split(',') if a.strip()]
        remote_addrs = [a.strip() for a in info['remote_addrs'].split(',') if a.strip()]
        version = '1' if 'IKEv1' in info['version'] else '2'

        if Connection.objects.filter(profile=conn_name).exists():
            return None, f"'{conn_name}' already exists in DB"

        conn = IKEv2PSK.objects.create(
            profile=conn_name,
            version=version,
            connection_type='site_to_site',
            initiate=True,
            enabled=False,
            send_certreq=False,
        )

        left = local_addrs[0] if local_addrs else ''
        right = remote_addrs[0] if remote_addrs else ''
        Address.objects.create(value=left, local_addresses=conn)
        Address.objects.create(value=right, remote_addresses=conn)

        PskAuthentication.objects.create(
            name='local-1', auth='psk', round=1, local=conn,
            psk='', identity=left,
        )
        PskAuthentication.objects.create(
            name='remote-1', auth='psk', round=1, remote=conn,
            psk='', identity=right,
        )

        for cname, cdetails in info['children'].items():
            child = Child.objects.create(
                name=cname, mode='tunnel', start_action='start', connection=conn,
            )
            for ts in cdetails['local_ts']:
                Address.objects.create(value=ts, local_ts=child)
            for ts in cdetails['remote_ts']:
                Address.objects.create(value=ts, remote_ts=child)

        return conn, f"Imported '{conn_name}' — set PSK via the edit form"

    except Exception as e:
        return None, f"Import failed: {e}"
