# Generated by Django 4.2.3 on 2023-08-03 12:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_alter_user_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='work_end_time',
            field=models.DateField(default=None),
        ),
        migrations.AlterField(
            model_name='user',
            name='work_start_time',
            field=models.DateField(default=None),
        ),
    ]