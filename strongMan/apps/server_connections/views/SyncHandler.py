from django.contrib import messages
from django.shortcuts import redirect

from strongMan.apps.server_connections.sync import auto_sync, import_from_vici


class SyncFromConfHandler:
    def __init__(self, request):
        self.request = request

    def handle(self):
        fmt, results = auto_sync()
        fmt_labels = {
            'ipsec':     'ipsec.conf',
            'swanctl':   'swanctl.conf',
            'vici-only': 'VICI live query',
        }
        messages.info(self.request,
            f"Sync method: {fmt_labels.get(fmt, fmt)}")
        for msg in results:
            level = (messages.SUCCESS
                     if 'error' not in msg.lower() and 'skip' not in msg.lower()
                     else messages.WARNING)
            messages.add_message(self.request, level, msg)
        if not results:
            messages.info(self.request, "No connections found")
        return redirect('server_connections:index')


class ImportFromViciHandler:
    def __init__(self, request):
        self.request = request

    def handle(self):
        conn_name = self.request.POST.get('name', '').strip()
        if not conn_name:
            messages.error(self.request, "No connection name provided")
            return redirect('server_connections:index')

        conn, msg = import_from_vici(conn_name)
        if conn:
            messages.success(self.request, msg)
        else:
            messages.warning(self.request, msg)
        return redirect('server_connections:index')
