from collections import OrderedDict

from django.db import models
from django.dispatch import receiver

from strongMan.apps.certificates.models import UserCertificate, CertificateDoNotDelete, PrivateKey
from .common import CertConDoNotDeleteMessage, KeyConDoNotDeleteMessage


@receiver(UserCertificate.should_prevent_delete_signal, sender=UserCertificate)
def prevent_cert_delete_if_cert_is_in_use(sender, **kwargs):
    cert = kwargs['instance']
    authentications = [ident.server_tls_identity for ident in cert.identities] + \
                      [ident.server_cert_identity for ident in cert.identities] + \
                      [cert.server_ca_cert_authentication]

    for auth in authentications:
        if auth.count() > 0:
            raise CertificateDoNotDelete(CertConDoNotDeleteMessage(auth.first().connection))
    return False, ""


@receiver(PrivateKey.should_prevent_delete_signal, sender=PrivateKey)
def prevent_key_delete_if_cert_is_in_use(sender, **kwargs):
    cert = kwargs['usercertificate']
    authentications = [ident.server_tls_identity for ident in cert.identities] + \
                      [ident.server_cert_identity for ident in cert.identities]
    for auth in authentications:
        if auth.count() > 0:
            raise CertificateDoNotDelete(KeyConDoNotDeleteMessage(auth.first().connection))
    return False, ""


class Child(models.Model):
    START_ACTION_CHOICES = (
        ('', "none"),
        ('start', "start"),
        ('trap', "trap"),
    )

    name = models.TextField()
    mode = models.TextField()
    start_action = models.CharField(max_length=5, choices=START_ACTION_CHOICES, null=True, blank=True,
                                    default=None)
    connection = models.ForeignKey("server_connections.Connection", null=True, blank=True, default=None,
                                   related_name='server_children', on_delete=models.CASCADE)
    dpd_action   = models.TextField(default='')
    mark         = models.TextField(default='')
    mark_in      = models.TextField(default='')
    mark_out     = models.TextField(default='')
    close_action = models.TextField(default='')
    keylife      = models.IntegerField(null=True, blank=True, default=None)
    rekeymargin  = models.IntegerField(null=True, blank=True, default=None)
    rekey        = models.BooleanField(null=True, blank=True, default=None)
    compress     = models.BooleanField(null=True, blank=True, default=None)

    def dict(self):
        child = OrderedDict()
        local_ts = [local_t.value for local_t in self.server_local_ts.all()]
        if local_ts and local_ts[0] != '':
            child['local_ts'] = local_ts
        remote_ts = [remote_t.value for remote_t in self.server_remote_ts.all()]
        if remote_ts and remote_ts[0] != '':
            child['remote_ts'] = remote_ts
        child['esp_proposals'] = [esp_proposal.type.rstrip('!') for esp_proposal in self.server_esp_proposals.all()]
        if self.start_action and self.start_action != '':
            child['start_action'] = self.start_action
        if self.dpd_action:
            child['dpd_action'] = self.dpd_action
        if self.mark:
            child['mark'] = self.mark
        if self.mark_in:
            child['mark_in'] = self.mark_in
        if self.mark_out:
            child['mark_out'] = self.mark_out
        if self.close_action:
            child['close_action'] = self.close_action
        if self.keylife is not None:
            child['life_time'] = self.keylife
        if self.rekeymargin is not None:
            child['rand_time'] = self.rekeymargin
        if self.rekey is False:
            child['rekey_time'] = 0
        if self.compress:
            child['ipcomp'] = 'yes'
        return child


class Address(models.Model):
    value = models.TextField()
    local_ts = models.ForeignKey(Child, null=True, blank=True, default=None,
                                 related_name='server_local_ts', on_delete=models.CASCADE)
    remote_ts = models.ForeignKey(Child, null=True, blank=True, default=None,
                                  related_name='server_remote_ts', on_delete=models.CASCADE)
    remote_addresses = models.ForeignKey("server_connections.Connection", null=True, blank=True,
                                         default=None, related_name='server_remote_addresses',
                                         on_delete=models.CASCADE)
    local_addresses = models.ForeignKey("server_connections.Connection", null=True, blank=True,
                                        default=None, related_name='server_local_addresses',
                                        on_delete=models.CASCADE)


class Proposal(models.Model):
    type = models.TextField()
    child = models.ForeignKey(Child, null=True, blank=True, default=None,
                              related_name='server_esp_proposals', on_delete=models.CASCADE)
    connection = models.ForeignKey("server_connections.Connection", null=True, blank=True, default=None,
                                   related_name='server_proposals', on_delete=models.CASCADE)


class LogMessage(models.Model):
    connection = models.ForeignKey("server_connections.Connection", null=True, blank=True, default=None,
                                   on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
