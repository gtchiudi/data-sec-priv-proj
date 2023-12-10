from django.urls import path
from . import views
from django.contrib import admin

urlpatterns = [
    path('handshake/', views.handshake, name='handshake'),
    path('health/', views.HealthView.as_view(), name='health'),
    path('login/', views.LoginView.as_view(), name='login'),
]
