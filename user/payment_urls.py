from django.urls import path
from .views import (
    # Importez vos nouvelles vues de paiement ici
    # Wallet management
    WalletProviderListView, MerchantWalletListCreateView, MerchantWalletDetailView,
    
    # Payment session management
    PaymentSessionCreateAPIView, PaymentSessionDetailAPIView,
    
    # Payment flow
    PaymentAuthenticateView, PaymentSelectWalletView, PaymentInitiateView, PaymentConfirmView,
    
    # Dashboard
    MerchantDashboardView, BuyerDashboardView,
    
    # Transactions
    TransactionListView, TransactionDetailView,
    
    # API Keys
    APIKeyListCreateView, APIKeyDetailView,

    WalletVerificationInitiateView, WalletVerificationConfirmView, WalletVerificationStatusView,
    
    # Utility
    payment_status_webhook, payment_widget_config
)

urlpatterns = [
    # ============================================================================
    # ECOMMERCE INTEGRATION ENDPOINTS
    # ============================================================================
    
    # Payment session management (for ecommerce platforms)
    path('payment/sessions/', PaymentSessionCreateAPIView.as_view(), name='payment-session-create'),
    path('payment/sessions/<uuid:session_id>/', PaymentSessionDetailAPIView.as_view(), name='payment-session-detail'),
    path('payment/sessions/<uuid:session_id>/config/', payment_widget_config, name='payment-widget-config'),
    
    # ============================================================================
    # PAYMENT WIDGET ENDPOINTS
    # ============================================================================
    
    # Payment flow (used by payment widget)
    path('payment/<uuid:session_id>/authenticate/', PaymentAuthenticateView.as_view(), name='payment-authenticate'),
    path('payment/<uuid:session_id>/select-wallet/', PaymentSelectWalletView.as_view(), name='payment-select-wallet'),
    path('payment/<uuid:session_id>/initiate/', PaymentInitiateView.as_view(), name='payment-initiate'),
    path('payment/<uuid:session_id>/confirm/', PaymentConfirmView.as_view(), name='payment-confirm'),
    
    # ============================================================================
    # MERCHANT DASHBOARD ENDPOINTS
    # ============================================================================
    
    # Wallet management
    path('merchants/wallets/providers/', WalletProviderListView.as_view(), name='wallet-providers'),
    path('merchants/wallets/', MerchantWalletListCreateView.as_view(), name='merchant-wallets'),
    path('merchants/wallets/<int:pk>/', MerchantWalletDetailView.as_view(), name='merchant-wallet-detail'),
    
    # Dashboard analytics
    path('merchants/dashboard/', MerchantDashboardView.as_view(), name='merchant-dashboard'),
    path('buyers/dashboard/', BuyerDashboardView.as_view(), name='buyer-dashboard'),
    
    # API key management
    path('merchants/api-keys/', APIKeyListCreateView.as_view(), name='api-keys'),
    path('merchants/api-keys/<int:pk>/', APIKeyDetailView.as_view(), name='api-key-detail'),
    
    # ============================================================================
    # TRANSACTION ENDPOINTS
    # ============================================================================
    
    path('transactions/', TransactionListView.as_view(), name='transactions'),
    path('transactions/<uuid:transaction_id>/', TransactionDetailView.as_view(), name='transaction-detail'),
    
    # ============================================================================
    # WEBHOOK ENDPOINTS
    # ============================================================================
    
    path('webhooks/payment-status/<uuid:session_id>/', payment_status_webhook, name='payment-status-webhook'),

    # ============================================================================
    # WALLET VERIFICATION ENDPOINTS
    # ============================================================================
    
    # Wallet verification flow
    path('merchants/wallets/verify/initiate/', WalletVerificationInitiateView.as_view(), name='wallet-verification-initiate'),
    path('merchants/wallets/verify/confirm/', WalletVerificationConfirmView.as_view(), name='wallet-verification-confirm'),
    path('merchants/wallets/verify/status/', WalletVerificationStatusView.as_view(), name='wallet-verification-status'),
]