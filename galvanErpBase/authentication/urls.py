from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from . import views
from .views import (
    register_user, verify_otp, resend_otp, LoginView, LogoutView,
    CookieTokenRefreshView, ForgotPasswordView, ResetPasswordView,
    send_email_verification, send_phone_verification, get_verification_status,
    UserUpdateDelete, AdminUserManage
)

urlpatterns = [
    path('register/', register_user, name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('token/refresh/', views.CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('verify-otp/', views.verify_otp, name='verify-otp'),
    path('resend-otp/', views.resend_otp, name='resend-otp'),
    path('send-email-otp/', send_email_verification, name='send_email_otp'),
    path('send-phone-otp/', send_phone_verification, name='send_phone_otp'),
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('verification-status/', views.get_verification_status, name='verification-status'),

    # New URLs for user management
    path('profile/', UserUpdateDelete.as_view(), name='user_profile'),
    path('users/<int:user_id>/', AdminUserManage.as_view(), name='admin_user_manage'),
]