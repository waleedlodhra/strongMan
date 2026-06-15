from datetime import timedelta
from django.utils import timezone
from django.http import JsonResponse
from strongMan.apps.connections.models.specific import LogMessage


class LogHandler(object):
    def __init__(self, request):
        self.id = int(request.POST.get('id'))

    def handle(self):
        self._delete_old_logs()
        if self.id < 0:
            logs = LogMessage.objects.all().order_by('timestamp')
        else:
            logs = LogMessage.objects.filter(pk__gt=self.id).order_by('timestamp')

        response = {'logs': []}
        for log in logs:
            response['logs'].append({
                'id':        log.id,
                'message':   log.message,
                'name':      log.connection.profile,
                'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            })
        return JsonResponse(response)

    def _delete_old_logs(self):
        time_threshold = timezone.now() - timedelta(minutes=10)
        LogMessage.objects.filter(timestamp__lt=time_threshold).delete()
