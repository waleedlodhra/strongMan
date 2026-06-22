from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('server_connections', '0003_psk_support'),
    ]

    operations = [
        # Child extra fields
        migrations.AddField(
            model_name='child',
            name='dpd_action',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='child',
            name='mark',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='child',
            name='mark_in',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='child',
            name='mark_out',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='child',
            name='close_action',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='child',
            name='keylife',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='child',
            name='rekeymargin',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='child',
            name='rekey',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='child',
            name='compress',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
        # Connection extra fields
        migrations.AddField(
            model_name='connection',
            name='dpd_delay',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='connection',
            name='dpd_timeout',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='connection',
            name='aggressive',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='connection',
            name='rightsourceip',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='connection',
            name='ikelifetime',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='connection',
            name='keyingtries',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
    ]
