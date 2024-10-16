# Generated by Django 5.1.1 on 2024-10-14 08:54

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='KeyPair',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('public_key', models.TextField()),
                ('private_key', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expire', models.DateTimeField()),
                ('status', models.CharField(choices=[('Active', 'Active'), ('Expired', 'Expired')], max_length=10)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='keypairs', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
