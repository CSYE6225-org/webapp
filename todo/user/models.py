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

