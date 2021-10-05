from django.contrib import admin
from django.urls import path
from . import views


urlpatterns = [
    path('self/', views.Register.as_view())
]