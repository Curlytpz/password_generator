from django.urls import path
from .views import PasswordGenerator

urlpatterns = [
    path('password/generate/<str:method>/', PasswordGenerator.as_view(), name='password-generate'),
]