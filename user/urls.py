# urls.py
from django.urls import path
from .views import (
    BuyerRegistrationView, MerchantRegistrationView, LoginView, LogoutView,
    UserProfileView, PasswordChangeView, PasswordResetRequestView,
    PasswordResetConfirmView, EmailVerificationView, ResendOTPView,
    user_status
)

urlpatterns = [
    # Authentication
    path('auth/buyer/register/', BuyerRegistrationView.as_view(), name='buyer-register'),
    path('auth/merchant/register/', MerchantRegistrationView.as_view(), name='merchant-register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    
    # Profile Management
    path('auth/profile/', UserProfileView.as_view(), name='user-profile'),
    path('auth/status/', user_status, name='user-status'),
    
    # Password Management
    path('auth/password/change/', PasswordChangeView.as_view(), name='password-change'),
    path('auth/password/reset/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # Email Verification
    path('auth/email/verify/', EmailVerificationView.as_view(), name='email-verify'),
    path('auth/email/resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
]