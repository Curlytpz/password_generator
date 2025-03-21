from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import UserRegistrationView  # Add this import
from . import views

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user_register'),

    # JWT Token Endpoints
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # Get access and refresh tokens
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh access token

    #A. Password Generation
    path('password/generate/random/', views.generate_random_password, name='generate_random_password'),
    path('password/generate/custom/', views.generate_custom_password, name='generate_custom_password'),
    path('password/generate/easy/', views.generate_easy_password, name='generate_easy_password'),
    path('password/generate/exclude-similar/', views.generate_exclude_similar_password, name='generate_exclude_similar_password'),
    path('password/expiration-reminder/', views.password_expiration_reminder, name='password_expiration_reminder'),

    # B. Password Strength Checking
    path('password/check/strength/', views.check_strength, name='check_strength'),
    path('password/check/common/', views.check_common, name='check_common'),
    path('password/check/repeated/', views.check_repeated, name='check_repeated'),
    path('password/calculate/entropy/', views.calculate_entropy, name='calculate_entropy'),
    path('password/check/leaked/', views.check_leaked, name='check_leaked'),
    #C. User-Friendly Features
    path('password/convert/weak-to-strong/', views.convert_weak_to_strong, name='convert_weak_to_strong'),
    path('password/estimate/crack-time/', views.estimate_crack_time, name='estimate_crack_time'),
    path('password/generate/passphrase/', views.generate_passphrase, name='generate_passphrase'),
    path('password/generate/passphrase/custom-separator/', views.generate_passphrase_custom_separator, name='generate_passphrase_custom_separator'),
    path('password/strength/report/', views.strength_report, name='strength_report'),
    #D. Security Enhancements
    path('password/recovery/reset/', views.password_recovery_reset, name='password_recovery_reset'),
    path('password/hash/', views.password_hash, name='password_hash'),
    path('password/validate/hash/', views.validate_hash, name='validate_hash'),
    path('password/encrypt/', views.encrypt_password, name='encrypt_password'),
    path('password/check/reuse/', views.check_reuse, name='check_reuse'),
]