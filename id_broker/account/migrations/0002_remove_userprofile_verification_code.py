# Generated by Django 4.1.2 on 2023-11-28 11:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("account", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="userprofile",
            name="verification_code",
        ),
    ]
