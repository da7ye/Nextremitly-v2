# urls.py
from django.urls import path
from .views import (
    BuyerRegistrationView, MerchantRegistrationView, LoginView, LogoutView, QRCodeDetailView, QRCodeListCreateView,
    UserProfileView, PasswordChangeView, PasswordResetRequestView,
    PasswordResetConfirmView, EmailVerificationView, ResendOTPView, initiate_qr_payment, public_qr_detail, public_qr_wallets, qr_code_stats, qr_payments_history,
    user_status,  verify_qr_payment_otp
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

     
    # path('qr-codes/', QRCodeListCreateView.as_view(), name='qr_codes_list_create'),
    # path('qr-codes/<str:id>/', QRCodeDetailView.as_view(), name='qr_code_detail'),
    # path('qr-codes/stats/overview/', qr_code_stats, name='qr_code_stats'),
    # path('qr-payments/history/', qr_payments_history, name='qr_payments_history'),
    
    # # ============================================================================
    # # PUBLIC QR CODE ROUTES (NO AUTH REQUIRED)
    # # ============================================================================
    # path('public/qr/<str:qr_id>/', public_qr_detail, name='public_qr_detail'),
    # path('public/qr/<str:qr_id>/pay/', initiate_qr_payment, name='initiate_qr_payment'),
    # path('public/qr-sessions/<uuid:session_id>/verify/', verify_qr_otp_and_pay, name='verify_qr_otp'),
    # path('public/qr/<str:qr_id>/wallets/', public_qr_wallets, name='public_qr_wallets'),

    # Protected routes - Merchant operations
    path('qr-codes/', QRCodeListCreateView.as_view(), name='qr-list-create'),
    path('qr-codes/<str:id>/', QRCodeDetailView.as_view(), name='qr-detail'),
    path('qr-codes/stats/overview/', qr_code_stats, name='qr-stats'),
    path('qr-codes/payments/history/', qr_payments_history, name='qr-payments-history'),
    
    # Public routes - Payment operations
    path('public/<str:qr_id>/', public_qr_detail, name='public-qr-detail'),
    path('public/<str:qr_id>/wallets/', public_qr_wallets, name='public-qr-wallets'),
    path('public/<str:qr_id>/initiate/', initiate_qr_payment, name='initiate-qr-payment'),
    path('public/verify/<uuid:session_id>/', verify_qr_payment_otp, name='verify-qr-payment'),
]