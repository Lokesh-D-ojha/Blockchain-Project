# Generated by Django 5.1 on 2024-09-05 05:19

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='profile',
            options={'permissions': [('view_own_documents', 'Can view own documents'), ('upload_document', 'Can upload document')]},
        ),
    ]
