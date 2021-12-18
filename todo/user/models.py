from django.db import models
from django.contrib.auth.models import AbstractBaseUser
import uuid
from django_bcrypt import *

# Create your models here.

class User(models.Model):
    first_name = models.CharField(max_length=254, default='')
    username = models.CharField(max_length=254, unique=True)
    last_name = models.CharField(max_length=254, default="")
    account_created = models.DateTimeField(auto_now_add=True)
    account_updated = models.DateTimeField(auto_now_add=True)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    password = models.CharField(max_length=254, default='')
    verified = models.BooleanField(default=False)
    verified_on = models.DateTimeField(auto_now_add=True)

class Image(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    filename = models.CharField(max_length=254, default='')
    user_id = models.ForeignKey(User,on_delete=models.CASCADE)
    url = models.CharField(max_length=254, default='')
    upload_date = models.DateTimeField(auto_now_add=True)

class Appoinments(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User,on_delete=models.CASCADE)
    doc_name = models.CharField(max_length=254, default='')
    apt_time = models.CharField(max_length=254, default='')

class MyDoctors(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(User,on_delete=models.CASCADE)
    doc_name = models.CharField(max_length=254, default='')
    address = models.CharField(max_length=254, default='')