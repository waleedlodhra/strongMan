"""
Write DB connections back to /etc/ipsec.conf and /etc/ipsec.secrets.
Called automatically after every GUI create / update / delete action.

Design:
  - Only PSK (IKEv2PSK) connections are written — certificate connections
    require cert files on disk and are managed separately.
  - Multi-child connections (e.g. branch2-host1 with two Child SAs) emit one
    ipsec.conf 'conn' block per child (standard stroke convention).
  - Writes are atomic: temp file + os.rename to avoid corrupt half-writes.
  - ipsec.secrets deduplicates by (left, right) peer pair.
"""
import os
import tempfile

CONF_PATH    = '/etc/ipsec.conf'
SECRETS_PATH = '/etc/ipsec.secrets'


# ─── helpers ──────────────────────────────────────────────────────────────────

def _atomic_write(path, content):
    dir_ = os.path.dirname(path) or '.'
    fd, tmp = tempfile.mkstemp(dir=dir_, prefix='.strongman_tmp_')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        os.rename(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _ike_version(version):
    return 'ikev1' if version == '1' else 'ikev2'


# ─── per-connection data extractors ───────────────────────────────────────────

def _conn_data(conn):
    """
    Return a dict with all the fields needed to write a conn block.
    Returns None if the connection type is not supported for write-back.
    """
    from strongMan.apps.server_connections.models.connections import IKEv2PSK
    from strongMan.apps.server_connections.models.authentication import PskAuthentication

    sub = conn.subclass()
    if not isinstance(sub, IKEv2PSK):
        return None

    left  = ''
    right = ''
    psk   = ''
    local_id  = ''
    remote_id = ''

    for auth in conn.server_local.all():
        s = auth.subclass()
        if isinstance(s, PskAuthentication):
            psk      = s.psk
            local_id = s.identity
            break
    for auth in conn.server_remote.all():
        s = auth.subclass()
        if isinstance(s, PskAuthentication):
            remote_id = s.identity
            break

    la = conn.server_local_addresses.first()
    ra = conn.server_remote_addresses.first()
    left  = la.value if la else local_id
    right = ra.value if ra else remote_id

    ike_prop = next((p.type for p in conn.server_proposals.all()), '')

    children = []
    for child in conn.server_children.all():
        lts = [a.value for a in child.server_local_ts.all()]
        rts = [a.value for a in child.server_remote_ts.all()]
        esp = next((p.type for p in child.server_esp_proposals.all()), '')
        children.append({
            'name':     child.name,
            'local_ts': lts,
            'remote_ts': rts,
            'esp':       esp,
            'start_action': child.start_action,
        })

    return {
        'profile':   conn.profile,
        'version':   conn.version,
        'initiate':  conn.initiate,
        'left':      la.value if la else '',
        'right':     ra.value if ra else '',
        'local_id':  local_id,
        'remote_id': remote_id,
        'ike':       ike_prop,
        'authby':    'secret',
        'psk':       psk,
        'children':  children,
    }


# ─── generators ───────────────────────────────────────────────────────────────

def generate_conf(connections=None):
    """Return full ipsec.conf content as a string."""
    from strongMan.apps.server_connections.models.connections import Connection
    if connections is None:
        connections = Connection.objects.all().order_by('id')

    lines = [
        '# Managed by strongMan GUI — changes are overwritten on next GUI save.',
        '# To add manual tunnels, use "Sync from ipsec.conf" after editing here.',
        '',
        'config setup',
        '    charondebug="all"',
        '',
    ]

    for conn in connections:
        data = _conn_data(conn)
        if data is None:
            continue

        auto = 'start' if data['initiate'] else 'add'

        for child in data['children']:
            lts_str = ','.join(child['local_ts'])
            rts_str = ','.join(child['remote_ts'])

            lines.append(f"conn {child['name']}")
            lines.append(f"    auto={auto}")
            lines.append(f"    type=tunnel")
            lines.append(f"    keyexchange={_ike_version(data['version'])}")
            lines.append(f"    authby={data['authby']}")
            lines.append(f"    left={data['left']}")
            if lts_str:
                lines.append(f"    leftsubnet={lts_str}")
            if data['local_id'] and data['local_id'] != data['left']:
                lines.append(f"    leftid={data['local_id']}")
            lines.append(f"    right={data['right']}")
            if rts_str:
                lines.append(f"    rightsubnet={rts_str}")
            if data['remote_id'] and data['remote_id'] != data['right']:
                lines.append(f"    rightid={data['remote_id']}")
            if data['ike']:
                lines.append(f"    ike={data['ike']}")
            if child['esp']:
                lines.append(f"    esp={child['esp']}")
            lines.append('')

    return '\n'.join(lines)


def generate_secrets(connections=None):
    """Return full ipsec.secrets content as a string."""
    from strongMan.apps.server_connections.models.connections import Connection
    if connections is None:
        connections = Connection.objects.all().order_by('id')

    lines = [
        '# Managed by strongMan GUI.',
        '',
    ]

    seen = set()
    for conn in connections:
        data = _conn_data(conn)
        if data is None or not data['psk']:
            continue
        key = (data['left'], data['right'])
        if key in seen:
            continue
        seen.add(key)
        left  = data['left']
        right = data['right']
        psk   = data['psk']
        lines.append(f'{left} {right} : PSK "{psk}"')

    return '\n'.join(lines) + '\n'


# ─── public API ───────────────────────────────────────────────────────────────

def write_all(conf_path=CONF_PATH, secrets_path=SECRETS_PATH):
    """
    Atomically write ipsec.conf and ipsec.secrets.
    Returns list of error strings (empty = success).
    """
    errors = []
    try:
        _atomic_write(conf_path, generate_conf())
    except Exception as e:
        errors.append(f'ipsec.conf write failed: {e}')
    try:
        _atomic_write(secrets_path, generate_secrets())
    except Exception as e:
        errors.append(f'ipsec.secrets write failed: {e}')
    return errors


def preview():
    """Return (conf_str, secrets_str) for display without writing."""
    return generate_conf(), generate_secrets()
