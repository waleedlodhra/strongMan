from django.http import JsonResponse
from strongMan.helper_apps.vici.wrapper.exception import ViciException

from strongMan.apps.server_connections.models.connections import Connection
from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper


def _d(val, default=''):
    """Decode bytes value to string; pass strings through."""
    if isinstance(val, (bytes, bytearray)):
        return val.decode('ascii', errors='replace')
    return str(val) if val is not None else default


class SaInfoHandler(object):
    def __init__(self, request):
        self.request = request
        self.id = int(request.POST.get('id'))

    @property
    def connection(self):
        return Connection.objects.get(pk=self.id).subclass()

    def handle(self):
        response = dict(id=self.connection.id, success=False)
        try:
            vici_wrapper = ViciWrapper()
            sas = vici_wrapper.get_sas_by(self.connection.profile)
            if sas:
                ikesas = [IkeSA(sa[self.connection.profile]) for sa in sas]
                response['child'] = [ike.__dict__ for ike in ikesas]
                response['success'] = True
        except ViciException as e:
            response['message'] = str(e)
        except Exception as e:
            print(e)
        return JsonResponse(response)


class IkeSA(object):
    # Note: vici Python library uses STRING keys; values are bytes.
    def __init__(self, sa):
        self.uniqueid      = _d(sa.get('uniqueid'))
        self.state         = _d(sa.get('state'))
        self.local_host    = _d(sa.get('local-host'))
        self.remote_host   = _d(sa.get('remote-host'))
        self.local_id      = _d(sa.get('local-id'))
        self.remote_id     = _d(sa.get('remote-id'))
        self.version       = _d(sa.get('version'))
        self.encr_alg      = _d(sa.get('encr-alg'))
        self.encr_keysize  = _d(sa.get('encr-keysize'))
        self.integ_alg     = _d(sa.get('integ-alg'))
        self.dh_group      = _d(sa.get('dh-group'))
        self.established   = _d(sa.get('established'),  '0')
        self.reauth_time   = _d(sa.get('reauth-time'),  '0')
        self.child_sas     = [ChildSA(cd) for cd in sa.get('child-sas', {}).values()]
        self.child_sas     = [c.__dict__ for c in self.child_sas]


class ChildSA(object):
    def __init__(self, sa):
        self.uniqueid     = _d(sa.get('uniqueid'))
        self.name         = _d(sa.get('name'))
        self.state        = _d(sa.get('state'))
        self.protocol     = _d(sa.get('protocol'))
        self.encr_alg     = _d(sa.get('encr-alg'))
        self.encr_keysize = _d(sa.get('encr-keysize'))
        self.integ_alg    = _d(sa.get('integ-alg'))
        lts = sa.get('local-ts',  [])
        rts = sa.get('remote-ts', [])
        self.local_ts     = ', '.join(_d(t) for t in lts) if lts else ''
        self.remote_ts    = ', '.join(_d(t) for t in rts) if rts else ''
        self.bytes_in     = _d(sa.get('bytes-in'),    '0')
        self.bytes_out    = _d(sa.get('bytes-out'),   '0')
        self.packets_in   = _d(sa.get('packets-in'),  '0')
        self.packets_out  = _d(sa.get('packets-out'), '0')
        self.install_time = _d(sa.get('install-time'), '0')
        self.rekey_time   = _d(sa.get('rekey-time'),  '0')
        self.life_time    = _d(sa.get('life-time'),   '0')
