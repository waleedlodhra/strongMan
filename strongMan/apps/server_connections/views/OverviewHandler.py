from django.contrib import messages
from django.shortcuts import render
from django_tables2 import RequestConfig

from strongMan.apps.server_connections.models.connections import Connection
from strongMan.apps.server_connections.sync import get_conf_connection_names, get_discovered_connections
from strongMan.helper_apps.vici.wrapper.exception import ViciException
from ..tables import ConnectionTable


class OverviewHandler(object):
    def __init__(self, request):
        self.request = request
        self.ENTRIES_PER_PAGE = 20

    def handle(self):
        try:
            return self._render()
        except ViciException as e:
            messages.warning(self.request, str(e))

    def _render(self):
        # Only show connections that exist in the active config file (ipsec.conf / swanctl.conf).
        # This prevents stale DB entries or manually-created GUI connections from cluttering
        # the list. If we can't parse the conf, fall back to showing everything.
        conf_names = get_conf_connection_names()
        if conf_names is not None:
            queryset = Connection.objects.filter(profile__in=conf_names)
        else:
            queryset = Connection.objects.all()

        table = ConnectionTable(queryset, request=self.request)
        RequestConfig(self.request, paginate={"per_page": self.ENTRIES_PER_PAGE}).configure(table)
        if len(queryset) == 0:
            table = None

        discovered, vici_error = get_discovered_connections()

        return render(self.request, 'server_connections/overview.html', {
            'table': table,
            'discovered': discovered,
            'vici_error': vici_error,
        })
