from django.http import JsonResponse
from django.shortcuts import render

from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper


def _d(val, default=''):
    """Decode bytes value; pass strings through."""
    if isinstance(val, (bytes, bytearray)):
        return val.decode('utf-8', errors='replace')
    return str(val) if val is not None else default


def _daemon_status(v):
    """Return formatted daemon stats dict."""
    try:
        st  = v.get_status()
        ver = v.get_version()
        uptime  = st.get('uptime',  {})
        workers = st.get('workers', {})
        active  = workers.get('active', {})
        ikesas  = st.get('ikesas',  {})
        return {
            'daemon':         _d(ver.get('daemon')),
            'version':        _d(ver.get('version')),
            'running':        _d(uptime.get('running')),
            'since':          _d(uptime.get('since')),
            'workers_total':  _d(workers.get('total')),
            'workers_idle':   _d(workers.get('idle')),
            'workers_active': (
                int(_d(active.get('critical', b'0')) or 0) +
                int(_d(active.get('high',     b'0')) or 0) +
                int(_d(active.get('medium',   b'0')) or 0) +
                int(_d(active.get('low',      b'0')) or 0)
            ),
            'ike_total':    _d(ikesas.get('total')),
            'ike_halfopen': _d(ikesas.get('half-open')),
            'scheduled':    _d(st.get('scheduled')),
        }
    except Exception as e:
        return {'error': str(e)}


def _all_sas(v):
    """Return list of formatted IKE SA dicts."""
    sas = []
    try:
        for sa_batch in v.session.list_sas():
            for name, ike in sa_batch.items():
                name_str = _d(name)
                encr = _d(ike.get('encr-alg'))
                ksz  = _d(ike.get('encr-keysize'))
                children = []
                for cname, cs in ike.get('child-sas', {}).items():
                    lts = [_d(t) for t in cs.get('local-ts',  [])]
                    rts = [_d(t) for t in cs.get('remote-ts', [])]
                    ce  = _d(cs.get('encr-alg'))
                    cks = _d(cs.get('encr-keysize'))
                    children.append({
                        'name':         _d(cs.get('name', cname)),
                        'uniqueid':     _d(cs.get('uniqueid')),
                        'state':        _d(cs.get('state')),
                        'protocol':     _d(cs.get('protocol')),
                        'encr':         ce + ('/' + cks if cks else ''),
                        'local_ts':     ', '.join(lts),
                        'remote_ts':    ', '.join(rts),
                        'bytes_in':     _d(cs.get('bytes-in'),    '0'),
                        'bytes_out':    _d(cs.get('bytes-out'),   '0'),
                        'packets_in':   _d(cs.get('packets-in'),  '0'),
                        'packets_out':  _d(cs.get('packets-out'), '0'),
                        'install_time': _d(cs.get('install-time'), '0'),
                        'rekey_time':   _d(cs.get('rekey-time'),  '0'),
                        'life_time':    _d(cs.get('life-time'),   '0'),
                    })
                sas.append({
                    'name':        name_str,
                    'uniqueid':    _d(ike.get('uniqueid')),
                    'version':     _d(ike.get('version')),
                    'state':       _d(ike.get('state')),
                    'local_host':  _d(ike.get('local-host')),
                    'remote_host': _d(ike.get('remote-host')),
                    'local_id':    _d(ike.get('local-id')),
                    'remote_id':   _d(ike.get('remote-id')),
                    'encr':        encr + ('/' + ksz if ksz else ''),
                    'integ':       _d(ike.get('integ-alg')),
                    'dh_group':    _d(ike.get('dh-group')),
                    'established': _d(ike.get('established'), '0'),
                    'reauth_time': _d(ike.get('reauth-time'), '0'),
                    'children':    children,
                })
    except Exception as e:
        return None, str(e)
    return sas, None


class MonitorPageHandler:
    def __init__(self, request):
        self.request = request

    def handle(self):
        return render(self.request, 'server_connections/monitor.html')


class MonitorDataHandler:
    def __init__(self, request):
        self.request = request

    def handle(self):
        try:
            v      = ViciWrapper()
            daemon = _daemon_status(v)
            sas, err = _all_sas(v)
            return JsonResponse({
                'success': True,
                'daemon':  daemon,
                'sas':     sas or [],
                'error':   err,
            })
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e), 'sas': [], 'daemon': {}})
