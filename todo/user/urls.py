from django.contrib import admin
from django.urls import path
from . import views


urlpatterns = [
    path('user/', views.Register.as_view()),
    path('appoinment/', views.CreateApplication.as_view()),
    path('mydoctors/', views.FavDoctors.as_view()),
    path('doctors/', views.DoctorsList.as_view()),
    path('user/self', views.GetUser.as_view()),
    path('verifyUserEmail', views.VerifyUser.as_view()),
    path('user/self/pic', views.GetProfilePic.as_view()),


]