from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render, redirect

from strongMan.apps.server_connections.models.connections import Connection
from strongMan.apps.server_connections.models.authentication import Authentication, PskAuthentication
from strongMan.apps.server_connections.conf_writer import write_all


def _get_psk_entries():
    """Return list of dicts with PSK data for all connections."""
    entries = []
    for conn in Connection.objects.all().order_by('id'):
        la = conn.server_local_addresses.first()
        ra = conn.server_remote_addresses.first()
        local_psk = None
        for auth in Authentication.objects.filter(local=conn):
            sub = auth.subclass()
            if isinstance(sub, PskAuthentication):
                local_psk = sub
                break
        if local_psk is None:
            continue
        entries.append({
            'conn_id':  conn.id,
            'profile':  conn.profile,
            'left':     la.value if la else '—',
            'right':    ra.value if ra else '—',
            'psk':      local_psk.psk,
            'auth_id':  local_psk.id,
        })
    return entries


class SecretsPageHandler:
    def __init__(self, request):
        self.request = request

    def handle(self):
        entries = _get_psk_entries()
        return render(self.request, 'server_connections/secrets.html', {'entries': entries})


class SecretsSaveHandler:
    def __init__(self, request):
        self.request = request

    def handle(self):
        auth_id = self.request.POST.get('auth_id')
        new_psk = self.request.POST.get('psk', '').strip()
        if not auth_id:
            messages.error(self.request, "Missing auth_id")
            return redirect('server_connections:secrets')

        try:
            psk_auth = PskAuthentication.objects.get(pk=auth_id)
            psk_auth.psk = new_psk
            psk_auth.save()
            errs = write_all()
            for e in errs:
                messages.warning(self.request, e)
            conn = psk_auth.local
            messages.success(self.request,
                f"PSK updated for {conn.profile if conn else '?'}.")
        except PskAuthentication.DoesNotExist:
            messages.error(self.request, "PSK entry not found.")
        return redirect('server_connections:secrets')
