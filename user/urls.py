# urls.py
from django.urls import path
from .views import (
    BuyerRegistrationView, MerchantRegistrationView, LoginView, LogoutView,
    UserProfileView, PasswordChangeView, PasswordResetRequestView,
    PasswordResetConfirmView, EmailVerificationView, ResendOTPView, public_qr_wallets,
    user_status,QRCodeListCreateView,QRCodeDetailView,qr_code_stats,qr_payments_history, public_qr_detail,initiate_qr_payment,
    verify_qr_otp_and_pay,
  
)
import random
import string
from decimal import Decimal
from django.conf import settings

def generate_otp(length=6):
    """Générer un code OTP aléatoire"""
    return ''.join(random.choices(string.digits, k=length))

def calculate_transaction_fee(amount):
    """Calculer les frais de transaction"""
    fee_percentage = Decimal('0.02')  # 2% de frais
    fee_amount = amount * fee_percentage
    net_amount = amount - fee_amount
    return fee_amount, net_amount

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

     
    path('qr-codes/', QRCodeListCreateView.as_view(), name='qr_codes_list_create'),
    path('qr-codes/<str:id>/', QRCodeDetailView.as_view(), name='qr_code_detail'),
    path('qr-codes/stats/overview/', qr_code_stats, name='qr_code_stats'),
    path('qr-payments/history/', qr_payments_history, name='qr_payments_history'),
    
    # ============================================================================
    # PUBLIC QR CODE ROUTES (NO AUTH REQUIRED)
    # ============================================================================
    path('public/qr/<str:qr_id>/', public_qr_detail, name='public_qr_detail'),
    path('public/qr/<str:qr_id>/pay/', initiate_qr_payment, name='initiate_qr_payment'),
    path('public/qr-sessions/<uuid:session_id>/verify/', verify_qr_otp_and_pay, name='verify_qr_otp'),
    # path('public/wallet-providers/', get_wallet_providers, name='wallet_providers'),
    path('public/qr/<str:qr_id>/wallets/', public_qr_wallets, name='public_qr_wallets'),
    
]
