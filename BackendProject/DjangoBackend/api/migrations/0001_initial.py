# Generated by Django 4.2.3 on 2023-08-08 08:57

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=255, unique=True, verbose_name='Email')),
                ('name', models.CharField(max_length=200)),
                ('phone_number', models.CharField(max_length=12)),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='checklist',
            fields=[
                ('project_name', models.TextField(default=None)),
                ('project_location', models.TextField(default=None)),
                ('supervisor_name', models.TextField(default=None)),
                ('subcontractor_name', models.TextField(default=None)),
                ('work_start_end_date', models.DateField(default=None)),
                ('wcp_esic_verification', models.TextField(default=None)),
                ('aadhar_card_verification', models.TextField(blank=True, default=None)),
                ('before_entry_body_scanning', models.TextField(default=None)),
                ('before_entry_bag_check', models.TextField(default=None)),
                ('physical_appearance', models.TextField(default=None)),
                ('before_entry_bag_tales_and_tool_check', models.TextField(default=None)),
                ('before_entry_bag_mental_health_check', models.TextField(default=None)),
                ('physical_health_check', models.TextField(default=None)),
                ('before_entry_bag_behavioral_check', models.TextField(default=None)),
                ('before_entry_bag_safety_helmet_check', models.TextField(default=None)),
                ('before_entry_bag_safety_shoes_check', models.TextField(default=None)),
                ('before_entry_bag_safety_jackets_check', models.TextField(default=None)),
                ('ladders_health_check', models.TextField(default=None)),
                ('work_place_check', models.TextField(default=None)),
                ('work_place_cleanliness_check', models.TextField(default=None)),
                ('balance_material_on_specified_area_check', models.TextField(default=None)),
                ('ladders_placement_check', models.TextField(default=None)),
                ('before_exit_body_scanning', models.TextField(default=None)),
                ('before_exit_bag_check', models.TextField(default=None)),
                ('before_exit_bag_tales_and_tool_check', models.TextField(default=None)),
                ('before_exit_bag_mental_health_check', models.TextField(default=None)),
                ('before_exit_bag_behavioral_check', models.TextField(default=None)),
                ('before_exit_bag_safety_helmet_check', models.TextField(default=None)),
                ('before_exit_bag_safety_shoes_check', models.TextField(default=None)),
                ('before_exit_bag_safety_jackets_check', models.TextField(default=None)),
                ('remark', models.TextField(default=None)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('auto_increment_id', models.AutoField(default=None, primary_key=True, serialize=False)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
