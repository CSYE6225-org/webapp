from django.contrib import admin
from django.urls import path
from . import views


urlpatterns = [
    path('user/', views.Register.as_view()),
    path('user/self', views.GetUser.as_view())

]