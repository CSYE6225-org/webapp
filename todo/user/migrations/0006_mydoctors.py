# Generated by Django 3.2.7 on 2021-12-18 07:01

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0005_appoinments'),
    ]

    operations = [
        migrations.CreateModel(
            name='MyDoctors',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('doc_name', models.CharField(default='', max_length=254)),
                ('address', models.CharField(default='', max_length=254)),
                ('user_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='user.user')),
            ],
        ),
    ]