# Generated by Django 5.1.1 on 2024-10-25 00:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('file', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='file_name',
            field=models.CharField(default='defult_name', max_length=500),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='file',
            name='status',
            field=models.CharField(choices=[('Unsigned', 'Unsigned'), ('Signed', 'Signed')], default='Unsigned', max_length=20),
        ),
    ]
