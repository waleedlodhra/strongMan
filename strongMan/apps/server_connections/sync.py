"""
Universal strongSwan → StrongMan sync library.

Supports all major strongSwan configuration formats:
  - ipsec.conf + ipsec.secrets  (legacy stroke, Ubuntu 18-20)
  - ipsec.d/*.conf includes      (split stroke configs)
  - swanctl.conf                 (modern swanctl, Ubuntu 22+)
  - swanctl/conf.d/*.conf        (split swanctl configs)
  - VICI-only (no config files)  (API-driven / any other setup)

auto_sync() detects which format is present and picks the right path.
All paths ultimately call the same DB upsert functions.
"""
import os
import re
import glob

from strongMan.apps.server_connections.models.connections import Connection, IKEv2PSK
from strongMan.apps.server_connections.models.specific import Child, Address, Proposal
from strongMan.apps.server_connections.models.authentication import Authentication, PskAuthentication


# ─── VICI socket auto-detection ───────────────────────────────────────────────

def find_vici_socket():
    candidates = [
        '/var/run/charon.vici',
        '/run/charon.vici',
        '/var/run/strongswan/charon.vici',
        '/run/strongswan/charon.vici',
    ]
    for cfg in ['/etc/strongswan.d/charon/vici.conf',
                '/etc/strongswan/strongswan.d/charon/vici.conf']:
        try:
            with open(cfg) as f:
                for line in f:
                    m = re.search(r'socket\s*=\s*unix://(.+)', line)
                    if m:
                        candidates.insert(0, m.group(1).strip())
        except FileNotFoundError:
            pass
    for path in candidates:
        if os.path.exists(path):
            return path
    return '/var/run/charon.vici'


# ─── ipsec.conf parser (stroke / legacy) ──────────────────────────────────────

def _resolve_ipsec_includes(path):
    lines = []
    base = os.path.dirname(path)
    try:
        with open(path) as f:
            for raw in f:
                stripped = raw.strip()
                if stripped.lower().startswith('include '):
                    pattern = stripped.split(None, 1)[1].strip()
                    if not os.path.isabs(pattern):
                        pattern = os.path.join(base, pattern)
                    for inc in sorted(glob.glob(pattern)):
                        lines.extend(_resolve_ipsec_includes(inc))
                else:
                    lines.append(raw)
    except FileNotFoundError:
        pass
    return lines


def parse_ipsec_conf(path='/etc/ipsec.conf'):
    """
    Parse ipsec.conf (+ includes) → list of conn dicts.

    Handles:
    - %default block: values merged as defaults into every conn
    - also=: recursive two-pass inheritance with cycle protection
    - _is_template: True for conns referenced by also= (used to skip empty template entries)
    """
    # ── First pass: collect raw blocks ──────────────────────────────────────
    raw_defaults = {}
    raw_conns    = {}
    raw_order    = []
    current_name = None
    current      = {}

    def _flush():
        nonlocal current_name, current
        if current_name is None:
            return
        if current_name == '%default':
            raw_defaults.update(current)
        else:
            if current_name not in raw_conns:
                raw_order.append(current_name)
            raw_conns[current_name] = current
        current_name = None
        current = {}

    for raw in _resolve_ipsec_includes(path):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('conn '):
            _flush()
            current_name = line.split(None, 1)[1].strip()
            current = {}
            continue
        if current_name is not None and '=' in line:
            key, _, val = line.partition('=')
            current[key.strip()] = val.strip()
    _flush()

    if not raw_conns:
        raise FileNotFoundError(f"No connections found in {path}")

    # ── Track which conns are referenced by also= (they are templates) ──────
    also_targets = set()
    for block in raw_conns.values():
        also = block.get('also', '').strip()
        if also:
            also_targets.add(also)

    # ── Second pass: resolve also= recursively (cycle-safe) ─────────────────
    def _merge_also(name, visited=None):
        if visited is None:
            visited = set()
        if name in visited or name not in raw_conns:
            return {}
        visited = visited | {name}
        block = raw_conns[name].copy()
        also  = block.pop('also', None)
        if also:
            base   = _merge_also(also.strip(), visited)
            merged = {**base, **block}
            return merged
        return block

    # ── Build final list: %default < also-chain < own-block ─────────────────
    connections = []
    for name in raw_order:
        resolved = _merge_also(name)
        final    = {**raw_defaults, **resolved, '_name': name}
        final['_is_template'] = (name in also_targets)
        connections.append(final)

    return connections


def parse_ipsec_secrets(path='/etc/ipsec.secrets'):
    psks = {}
    secrets_files = [path]
    d = os.path.join(os.path.dirname(path), 'ipsec.d')
    secrets_files += sorted(glob.glob(os.path.join(d, '*.secrets')))
    for p in secrets_files:
        try:
            with open(p) as f:
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


# ─── swanctl.conf parser (modern vici / swanctl) ──────────────────────────────

def _swanctl_files():
    candidates = []
    for path in ['/etc/swanctl/swanctl.conf',
                 '/etc/strongswan/swanctl/swanctl.conf']:
        if os.path.isfile(path):
            candidates.append(path)
    for pattern in ['/etc/swanctl/conf.d/*.conf',
                    '/etc/strongswan/swanctl/conf.d/*.conf']:
        candidates.extend(sorted(glob.glob(pattern)))
    return candidates


def _parse_swanctl_block(text):
    result = {}
    i = 0
    text = text.strip()
    while i < len(text):
        while i < len(text) and text[i] in ' \t\r\n':
            i += 1
        if i >= len(text):
            break
        if text[i] == '#':
            while i < len(text) and text[i] != '\n':
                i += 1
            continue
        key_start = i
        while i < len(text) and text[i] not in '={#\n':
            i += 1
        key = text[key_start:i].strip()
        if not key:
            i += 1
            continue
        while i < len(text) and text[i] in ' \t':
            i += 1
        if i >= len(text):
            break
        if text[i] == '=':
            i += 1
            while i < len(text) and text[i] in ' \t':
                i += 1
            val_start = i
            while i < len(text) and text[i] != '\n':
                i += 1
            val = text[val_start:i].strip().strip('"').strip("'")
            if key:
                result[key] = val
        elif text[i] == '{':
            depth = 1
            i += 1
            block_start = i
            while i < len(text) and depth > 0:
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                i += 1
            block_text = text[block_start:i - 1]
            if key:
                result[key] = _parse_swanctl_block(block_text)
        else:
            i += 1
    return result


def parse_swanctl_conf(paths=None):
    if paths is None:
        paths = _swanctl_files()

    merged = {}
    for path in paths:
        try:
            with open(path) as f:
                content = f.read()
            parsed = _parse_swanctl_block(content)
            for section in ('connections', 'secrets'):
                if section in parsed and isinstance(parsed[section], dict):
                    merged.setdefault(section, {}).update(parsed[section])
        except FileNotFoundError:
            pass

    conns_raw   = merged.get('connections', {})
    secrets_raw = merged.get('secrets', {})

    psks = {}
    for sec_name, sec in secrets_raw.items():
        if not isinstance(sec, dict):
            continue
        secret = sec.get('secret', '')
        if not secret:
            continue
        ids = [v for k, v in sec.items() if k.startswith('id')]
        if len(ids) >= 2:
            psks.setdefault((ids[0], ids[1]), secret)
            psks.setdefault((ids[1], ids[0]), secret)
        elif len(ids) == 1:
            psks.setdefault((ids[0], '%any'), secret)
        else:
            psks.setdefault(('%any', '%any'), secret)

    connections = []
    for conn_name, conn in conns_raw.items():
        if not isinstance(conn, dict):
            continue
        local_addrs  = conn.get('local_addrs', '')
        remote_addrs = conn.get('remote_addrs', '')
        if not local_addrs and not remote_addrs:
            continue

        version  = conn.get('version', '2')
        ike_prop = conn.get('proposals', '')

        local_auth = 'pubkey'
        for k, v in conn.items():
            if k.startswith('local') and isinstance(v, dict):
                local_auth = v.get('auth', 'pubkey')
                break

        children = conn.get('children', {})
        if not isinstance(children, dict) or not children:
            children = {conn_name: conn}

        for child_name, child in children.items():
            if not isinstance(child, dict):
                continue
            lts   = child.get('local_ts', '')
            rts   = child.get('remote_ts', '')
            esp   = child.get('esp_proposals', '')
            start = child.get('start_action', 'none')
            connections.append({
                '_name':       child_name,
                '_ike_name':   conn_name,
                '_is_template': False,
                'left':        local_addrs.split(',')[0].strip() if local_addrs else '',
                'right':       remote_addrs.split(',')[0].strip() if remote_addrs else '',
                'keyexchange': f'ikev{version}',
                'authby':      'secret' if local_auth == 'psk' else local_auth,
                'ike':         ike_prop,
                'leftsubnet':  lts,
                'rightsubnet': rts,
                'esp':         esp,
                'auto':        'start' if start in ('start', 'trap') else 'add',
            })

    return connections, psks


def _has_real_swanctl_conns(paths=None):
    if paths is None:
        paths = _swanctl_files()
    for path in paths:
        try:
            with open(path) as f:
                content = f.read()
            parsed = _parse_swanctl_block(content)
            conns  = parsed.get('connections', {})
            for name, block in conns.items():
                if isinstance(block, dict) and (
                    block.get('local_addrs') or block.get('remote_addrs')
                ):
                    return True
        except FileNotFoundError:
            pass
    return False


# ─── PSK lookup ───────────────────────────────────────────────────────────────

def lookup_psk(psks, left, right):
    for key in [(left, right), (right, left), (left, '%any'), ('%any', right), ('%any', '%any')]:
        if key in psks:
            return psks[key]
    return ''


# ─── helpers ──────────────────────────────────────────────────────────────────

def _detect_version(conf):
    ke = conf.get('keyexchange', 'ikev2').lower()
    if ke == 'ikev1':
        return '1'
    elif ke == 'ikev2':
        return '2'
    else:
        return '0'   # 'ike' = any version


def _normalise_proposal(raw):
    # Keep '!' — it's stripped at VICI send time in dict() methods, not in DB
    return raw.strip() if raw else None


def _is_psk_auth(conf):
    """Return True for any PSK-based authentication variant."""
    authby = conf.get('authby', '').lower()
    if authby in ('secret', 'psk', 'xauthpsk', 'xauth', 'xauthpsk+xauthpsk'):
        return True
    # leftauth/rightauth split format
    leftauth  = conf.get('leftauth',  '').lower()
    rightauth = conf.get('rightauth', '').lower()
    if leftauth in ('psk', 'secret', 'xauth') or rightauth in ('psk', 'secret', 'xauth'):
        return True
    return False


def _ike_group_key(conf):
    """Group key for connections that share the same IKE SA (same peer + crypto)."""
    return (
        conf.get('left',        ''),
        conf.get('right',       ''),
        conf.get('keyexchange', 'ikev2').lower(),
        conf.get('authby',      'pubkey').lower(),
        conf.get('ike',         ''),
        conf.get('type',        'tunnel').lower(),   # separate transport from tunnel
    )


# ─── DB upsert ────────────────────────────────────────────────────────────────

def upsert_connection_group(primary_conf, child_confs, psks):
    """
    Create/update ONE DB Connection for a group of conn blocks sharing the same
    IKE SA. Each conf block (that has subnets or is standalone) becomes a Child SA.
    Template conns (referenced by also=, no subnets) are skipped as children.
    Returns (conn, created, message).
    """
    name = primary_conf['_name']

    if not _is_psk_auth(primary_conf):
        authby = primary_conf.get('authby', 'pubkey')
        skipped = [c['_name'] for c in [primary_conf] + child_confs]
        return None, False, f"{', '.join(skipped)}: skipped (auth={authby} — certificate/EAP, add manually)"

    left      = primary_conf.get('left',  '')
    right     = primary_conf.get('right', '')
    version   = _detect_version(primary_conf)
    ike_prop  = _normalise_proposal(primary_conf.get('ike', ''))
    auto      = primary_conf.get('auto', 'ignore')
    initiate  = auto in ('start', 'route')
    psk_value = lookup_psk(psks, left, right)

    existing = Connection.objects.filter(profile=name).first()
    created  = existing is None

    if existing:
        conn = existing.subclass()
        conn.version  = version
        conn.initiate = initiate
        conn.save()
    else:
        conn = IKEv2PSK.objects.create(
            profile=name, version=version, connection_type='site_to_site',
            initiate=initiate, enabled=True, send_certreq=False,
        )

    conn.server_local_addresses.all().delete()
    conn.server_remote_addresses.all().delete()
    Address.objects.create(value=left,  local_addresses=conn)
    Address.objects.create(value=right, remote_addresses=conn)

    conn.server_proposals.all().delete()
    if ike_prop:
        Proposal.objects.create(type=ike_prop, connection=conn)

    Authentication.objects.filter(local=conn).delete()
    Authentication.objects.filter(remote=conn).delete()
    PskAuthentication.objects.create(
        name='local-1', auth='psk', round=1, local=conn, psk=psk_value, identity=left,
    )
    PskAuthentication.objects.create(
        name='remote-1', auth='psk', round=1, remote=conn, psk='', identity=right,
    )

    # ── Create Child SAs ─────────────────────────────────────────────────────
    conn.server_children.all().delete()

    all_confs = [primary_conf] + child_confs

    # Does any conf in this group have explicit traffic selectors?
    has_any_subnets = any(
        c.get('leftsubnet', '').strip() or c.get('rightsubnet', '').strip()
        for c in all_confs
    )

    created_children = 0
    for conf in all_confs:
        lts = [s.strip() for s in conf.get('leftsubnet', '').split(',') if s.strip()]
        rts = [s.strip() for s in conf.get('rightsubnet', '').split(',') if s.strip()]

        # Skip template conns (referenced by also=, no subnets) when the group has
        # real children with subnets — they are pure IKE SA config templates.
        if conf.get('_is_template') and not lts and not rts and has_any_subnets:
            continue

        esp   = _normalise_proposal(conf.get('esp', ''))
        child = Child(name=conf['_name'], mode='tunnel', start_action='start', connection=conn)
        child.save()

        for ts in lts:
            Address.objects.create(value=ts, local_ts=child)
        for ts in rts:
            Address.objects.create(value=ts, remote_ts=child)
        if esp:
            Proposal.objects.create(type=esp, child=child)
        created_children += 1

    # If nothing was created (all were templates — shouldn't happen, but guard):
    if created_children == 0:
        child = Child(name=name, mode='tunnel', start_action='start', connection=conn)
        child.save()

    # Build display list of real (non-template) children
    real_child_names = [c['_name'] for c in all_confs if not (
        c.get('_is_template') and not c.get('leftsubnet', '').strip()
        and not c.get('rightsubnet', '').strip() and has_any_subnets
    )]
    # Skip the primary name itself from children display to avoid redundancy
    display_children = [n for n in real_child_names if n != name]
    verb  = 'created' if created else 'updated'
    extra = f" (children: {', '.join(display_children)})" if display_children else ""
    return conn, created, f"{name}: {verb}{extra}"


def upsert_connection(conf, psks):
    return upsert_connection_group(conf, [], psks)


def _apply_groups(conns, psks):
    """Group conn list by IKE SA key, remove stale standalone entries, upsert."""
    groups = {}
    order  = []
    for conf in conns:
        key = _ike_group_key(conf)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(conf)

    # Collect names that appear as non-primary (child) profiles in a group
    child_profiles = set()
    for key in order:
        group = groups[key]
        for c in group[1:]:
            child_profiles.add(c['_name'])

    messages = []
    removed  = []
    for profile in child_profiles:
        stale = Connection.objects.filter(profile=profile).first()
        if stale:
            stale.delete()
            removed.append(profile)
    if removed:
        messages.append(f"Removed stale standalone entries: {', '.join(removed)}")

    for key in order:
        group = groups[key]
        _, _, msg = upsert_connection_group(group[0], group[1:], psks)
        messages.append(msg)
    return messages


def sync_cleanup(conf_names):
    """Remove DB connections whose profile is not in conf_names."""
    removed = []
    for conn in Connection.objects.all():
        if conn.profile not in conf_names:
            conn.delete()
            removed.append(conn.profile)
    return removed


# ─── format-specific sync functions ───────────────────────────────────────────

def sync_from_conf(conf_path='/etc/ipsec.conf', secrets_path='/etc/ipsec.secrets'):
    """Sync from ipsec.conf + ipsec.secrets. Also removes DB entries no longer in conf."""
    try:
        conns = parse_ipsec_conf(conf_path)
    except FileNotFoundError:
        return [f"Error: {conf_path} not found or has no connections"]
    psks = parse_ipsec_secrets(secrets_path)

    messages = _apply_groups(conns, psks)

    # Remove stale DB connections not present in ipsec.conf
    conf_names = {c['_name'] for c in conns}
    removed = sync_cleanup(conf_names)
    if removed:
        messages.append(f"Cleaned up stale entries: {', '.join(removed)}")

    return messages


def sync_from_swanctl(paths=None):
    """Sync from swanctl.conf / conf.d/*.conf."""
    conns, psks = parse_swanctl_conf(paths)
    if not conns:
        return ["No connections found in swanctl config files"]
    messages = _apply_groups(conns, psks)

    conf_names = {c['_name'] for c in conns}
    removed = sync_cleanup(conf_names)
    if removed:
        messages.append(f"Cleaned up stale entries: {', '.join(removed)}")

    return messages


def sync_from_vici():
    """
    VICI-first sync: imports whatever charon has loaded.
    PSKs are left blank (user fills them via PSK Secrets page).
    """
    from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper
    socket = find_vici_socket()
    try:
        v = ViciWrapper(socket_path=socket)
    except Exception as e:
        return [f"VICI socket error ({socket}): {e}"]

    messages  = []
    seen_names = set()

    def _dv(v, default=''):
        return v.decode() if isinstance(v, bytes) else (str(v) if v else default)

    try:
        for conn_batch in v.session.list_conns():
            for ike_name, ike in conn_batch.items():
                ike_name = ike_name if isinstance(ike_name, str) else ike_name.decode()
                if ike_name in seen_names:
                    continue
                seen_names.add(ike_name)

                local_auth = 'unknown'
                for k, sub in ike.items():
                    k_str = k if isinstance(k, str) else k.decode()
                    if k_str.startswith('local-') and isinstance(sub, dict):
                        cls        = sub.get('class', sub.get(b'class', b''))
                        local_auth = cls.decode() if isinstance(cls, bytes) else str(cls)
                        break

                la    = ike.get('local_addrs',  ike.get(b'local_addrs',  []))
                ra    = ike.get('remote_addrs', ike.get(b'remote_addrs', []))
                left  = _dv(la[0]) if la else ''
                right = _dv(ra[0]) if ra else ''
                ver   = _dv(ike.get('version', ike.get(b'version', b'2')))
                ver   = '1' if 'IKEv1' in ver or ver == '1' else '2'

                children = ike.get('children', ike.get(b'children', {}))
                if not children:
                    children = {ike_name: {}}

                primary     = None
                child_confs = []
                for cname, cdetails in children.items():
                    cname_str = cname if isinstance(cname, str) else cname.decode()
                    lts_raw   = cdetails.get('local-ts',  cdetails.get(b'local-ts',  []))
                    rts_raw   = cdetails.get('remote-ts', cdetails.get(b'remote-ts', []))
                    conf = {
                        '_name':        cname_str,
                        '_is_template': False,
                        'left':         left,
                        'right':        right,
                        'keyexchange':  f'ikev{ver}',
                        'authby':       'secret' if 'pre-shared' in local_auth else local_auth,
                        'leftsubnet':   ','.join(_dv(t) for t in lts_raw),
                        'rightsubnet':  ','.join(_dv(t) for t in rts_raw),
                        'auto':         'start',
                    }
                    if primary is None:
                        primary = conf
                        primary['_name'] = ike_name
                    else:
                        child_confs.append(conf)

                if primary is None:
                    continue

                existing = Connection.objects.filter(profile=ike_name).first()
                if existing:
                    psk_val = ''
                    for auth in Authentication.objects.filter(local=existing):
                        sub = auth.subclass()
                        if isinstance(sub, PskAuthentication) and sub.psk:
                            psk_val = sub.psk
                            break
                    psks_for_upsert = {(left, right): psk_val} if psk_val else {}
                else:
                    psks_for_upsert = {}

                _, _, msg  = upsert_connection_group(primary, child_confs, psks_for_upsert)
                psk_note   = '' if existing else ' (PSK blank — set via PSK Secrets page)'
                messages.append(msg + psk_note)
    except Exception as e:
        messages.append(f"VICI error: {e}")
    return messages


# ─── auto-detect and sync ─────────────────────────────────────────────────────

def detect_config_format():
    for p in ['/etc/ipsec.conf', '/etc/strongswan/ipsec.conf']:
        if os.path.isfile(p):
            try:
                conns = parse_ipsec_conf(p)
                if conns:
                    return 'ipsec'
            except Exception:
                pass

    if _has_real_swanctl_conns():
        return 'swanctl'

    return 'vici-only'


def auto_sync():
    """Detect config format and run the appropriate sync. Returns (format_used, messages)."""
    fmt = detect_config_format()

    if fmt == 'ipsec':
        conf_path    = '/etc/ipsec.conf'
        secrets_path = '/etc/ipsec.secrets'
        for p in ['/etc/strongswan/ipsec.conf']:
            if os.path.isfile(p):
                conf_path    = p
                secrets_path = os.path.join(os.path.dirname(p), 'ipsec.secrets')
                break
        msgs = sync_from_conf(conf_path, secrets_path)

    elif fmt == 'swanctl':
        msgs = sync_from_swanctl()

    else:
        msgs = sync_from_vici()

    return fmt, msgs


# ─── helper: names currently in the active conf file ─────────────────────────

def get_conf_connection_names():
    """
    Return set of connection profile names from the active config file.
    Returns None if the format cannot be determined or parsed.
    """
    try:
        fmt = detect_config_format()
        if fmt == 'ipsec':
            conns = parse_ipsec_conf()
            return {c['_name'] for c in conns}
        elif fmt == 'swanctl':
            conns, _ = parse_swanctl_conf()
            return {c['_name'] for c in conns}
    except Exception:
        pass
    return None


# ─── VICI discovery ───────────────────────────────────────────────────────────

def _decode(val):
    if isinstance(val, (bytes, bytearray)):
        return val.decode('utf-8', errors='replace')
    return str(val) if val is not None else ''


def get_vici_conn_details(name, raw):
    version      = _decode(raw.get('version', '?'))
    local_addrs  = [_decode(a) for a in raw.get('local_addrs',  [])]
    remote_addrs = [_decode(a) for a in raw.get('remote_addrs', [])]
    auth_class   = 'unknown'
    for k, sub in raw.items():
        if (k if isinstance(k, str) else k.decode()).startswith('local-') and isinstance(sub, dict):
            auth_class = _decode(sub.get('class', ''))
            break
    children = {}
    for cname, cdetails in raw.get('children', {}).items():
        cname_str = _decode(cname)
        lts = [_decode(t) for t in cdetails.get('local-ts',  [])]
        rts = [_decode(t) for t in cdetails.get('remote-ts', [])]
        children[cname_str] = {'local_ts': lts, 'remote_ts': rts}
    return {
        'name':         name,
        'version':      version,
        'auth_class':   auth_class,
        'local_addrs':  ', '.join(local_addrs),
        'remote_addrs': ', '.join(remote_addrs),
        'children':     children,
    }


def get_discovered_connections():
    """Return connections charon knows about that are not yet in the DB."""
    from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper
    try:
        v          = ViciWrapper(socket_path=find_vici_socket())
        db_profiles = set(Connection.objects.values_list('profile', flat=True))
        discovered  = []
        for conn in v.session.list_conns():
            for name, details in conn.items():
                name_str = name if isinstance(name, str) else name.decode()
                if name_str not in db_profiles:
                    discovered.append(get_vici_conn_details(name_str, details))
        return discovered, None
    except Exception as e:
        return [], str(e)


def import_from_vici(conn_name):
    """Import a single VICI-discovered connection into the DB (PSK left blank)."""
    from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper
    try:
        v        = ViciWrapper(socket_path=find_vici_socket())
        raw_list = {}
        for conn in v.session.list_conns():
            for name, details in conn.items():
                name_str          = name if isinstance(name, str) else name.decode()
                raw_list[name_str] = details

        if conn_name not in raw_list:
            return None, f"Connection '{conn_name}' not found in VICI"
        if Connection.objects.filter(profile=conn_name).exists():
            return None, f"'{conn_name}' already exists in DB"

        info  = get_vici_conn_details(conn_name, raw_list[conn_name])
        la    = [a.strip() for a in info['local_addrs'].split(',')  if a.strip()]
        ra    = [a.strip() for a in info['remote_addrs'].split(',') if a.strip()]
        ver   = '1' if 'IKEv1' in info['version'] else '2'

        conn  = IKEv2PSK.objects.create(
            profile=conn_name, version=ver, connection_type='site_to_site',
            initiate=True, enabled=False, send_certreq=False,
        )
        left  = la[0] if la else ''
        right = ra[0] if ra else ''
        Address.objects.create(value=left,  local_addresses=conn)
        Address.objects.create(value=right, remote_addresses=conn)
        PskAuthentication.objects.create(name='local-1',  auth='psk', round=1, local=conn,  psk='', identity=left)
        PskAuthentication.objects.create(name='remote-1', auth='psk', round=1, remote=conn, psk='', identity=right)
        for cname, cdetails in info['children'].items():
            child = Child(name=cname, mode='tunnel', start_action='start', connection=conn)
            child.save()
            for ts in cdetails['local_ts']:
                Address.objects.create(value=ts, local_ts=child)
            for ts in cdetails['remote_ts']:
                Address.objects.create(value=ts, remote_ts=child)
        return conn, f"Imported '{conn_name}' — set PSK via the PSK Secrets page"
    except Exception as e:
        return None, f"Import failed: {e}"
