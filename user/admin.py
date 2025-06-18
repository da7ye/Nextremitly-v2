# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustUser, Buyer, Merchant, OTP_User,WalletVerificationOTP


class CustUserAdmin(UserAdmin):
    list_display = ('email', 'nom_complet', 'user_type', 'is_verified', 'is_active', 'date_joined')
    list_filter = ('user_type', 'is_verified', 'is_active', 'date_joined')
    search_fields = ('email', 'nom_complet', 'numero_telephone')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('nom_complet', 'adrese', 'numero_telephone')}),
        ('Account info', {'fields': ('user_type', 'is_verified', 'date_verified')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'user_type'),
        }),
    )


class BuyerAdmin(CustUserAdmin):
    list_display = ('email', 'nom_complet', 'preferred_payment_method', 'phone_verified', 'is_verified', 'date_joined')
    
    fieldsets = CustUserAdmin.fieldsets + (
        ('Buyer Info', {'fields': ('preferred_payment_method', 'date_of_birth', 'phone_verified')}),
    )


class MerchantAdmin(CustUserAdmin):
    list_display = ('email', 'business_name', 'category', 'verification_status', 'activation_status', 'date_joined')
    list_filter = ('verification_status', 'activation_status', 'category', 'date_joined')
    
    fieldsets = CustUserAdmin.fieldsets + (
        ('Business Info', {'fields': ('business_name', 'website', 'category', 'bank_account_number')}),
        ('Status', {'fields': ('verification_status', 'activation_status')}),
    )
    
    actions = ['approve_merchants', 'deactivate_merchants']
    
    def approve_merchants(self, request, queryset):
        queryset.update(verification_status=True, activation_status=True)
        self.message_user(request, f"{queryset.count()} merchants were approved.")
    approve_merchants.short_description = "Approve selected merchants"
    
    def deactivate_merchants(self, request, queryset):
        queryset.update(activation_status=False)
        self.message_user(request, f"{queryset.count()} merchants were deactivated.")
    deactivate_merchants.short_description = "Deactivate selected merchants"


class OTPUserAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'purpose', 'is_used', 'created_at', 'is_expired_display')
    list_filter = ('purpose', 'is_used', 'created_at')
    search_fields = ('user__email', 'code')
    readonly_fields = ('created_at',)
    
    def is_expired_display(self, obj):
        return obj.is_expired()
    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expired'


# Register the models
admin.site.register(CustUser, CustUserAdmin)
admin.site.register(Buyer, BuyerAdmin)
admin.site.register(Merchant, MerchantAdmin)
admin.site.register(OTP_User, OTPUserAdmin)

# Customize admin site
admin.site.site_header = "Payment Platform Administration"
admin.site.site_title = "Payment Platform Admin"
admin.site.index_title = "Welcome to Payment Platform Administration"

#! Nextremitly admin.py
# payment_admin.py - Add these to your admin.py file

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    WalletProvider, MerchantWallet, PaymentSession, Transaction, 
    PaymentOTP, WebhookLog, APIKey
)


@admin.register(WalletProvider)
class WalletProviderAdmin(admin.ModelAdmin):
    list_display = ('display_name', 'name', 'is_active', 'supports_otp')
    list_filter = ('is_active', 'supports_otp')
    search_fields = ('name', 'display_name')
    list_editable = ('is_active',)


@admin.register(MerchantWallet)
class MerchantWalletAdmin(admin.ModelAdmin):
    list_display = ('merchant_name', 'provider_name', 'wallet_name', 'wallet_id', 'is_active', 'is_primary', 'created_at')
    list_filter = ('provider', 'is_active', 'is_primary', 'created_at')
    search_fields = ('merchant__business_name', 'wallet_name', 'wallet_id')
    list_select_related = ('merchant', 'provider')
    
    def merchant_name(self, obj):
        return obj.merchant.business_name
    merchant_name.short_description = 'Merchant'
    
    def provider_name(self, obj):
        return obj.provider.display_name
    provider_name.short_description = 'Provider'


@admin.register(PaymentSession)
class PaymentSessionAdmin(admin.ModelAdmin):
    list_display = ('session_id_short', 'merchant_name', 'amount', 'currency', 'status', 'created_at', 'is_expired_display')
    list_filter = ('status', 'currency', 'created_at')
    search_fields = ('session_id', 'merchant__business_name', 'customer_email')
    readonly_fields = ('session_id', 'created_at', 'updated_at')
    list_select_related = ('merchant', 'authenticated_user', 'selected_wallet')
    
    fieldsets = (
        ('Session Info', {
            'fields': ('session_id', 'merchant', 'status', 'created_at', 'updated_at', 'expires_at')
        }),
        ('Payment Details', {
            'fields': ('amount', 'currency', 'description')
        }),
        ('Customer Info', {
            'fields': ('customer_email', 'customer_phone', 'authenticated_user')
        }),
        ('Payment Flow', {
            'fields': ('selected_wallet', 'customer_wallet_phone')
        }),
        ('Ecommerce Integration', {
            'fields': ('success_url', 'cancel_url', 'webhook_url', 'metadata')
        }),
    )
    
    def session_id_short(self, obj):
        return str(obj.session_id)[:8] + '...'
    session_id_short.short_description = 'Session ID'
    
    def merchant_name(self, obj):
        return obj.merchant.business_name
    merchant_name.short_description = 'Merchant'
    
    def is_expired_display(self, obj):
        return obj.is_expired()
    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expired'


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('transaction_id_short', 'transaction_type', 'amount', 'currency', 'status', 'merchant_name', 'created_at')
    list_filter = ('transaction_type', 'status', 'currency', 'created_at', 'sender_wallet_provider')
    search_fields = ('transaction_id', 'external_transaction_id', 'merchant__business_name', 'sender__email')
    readonly_fields = ('transaction_id', 'net_amount', 'created_at', 'updated_at', 'completed_at')
    list_select_related = ('merchant', 'sender', 'receiver', 'sender_wallet_provider')
    
    fieldsets = (
        ('Transaction Info', {
            'fields': ('transaction_id', 'transaction_type', 'status', 'external_transaction_id')
        }),
        ('Parties', {
            'fields': ('sender', 'receiver', 'merchant')
        }),
        ('Amounts', {
            'fields': ('amount', 'currency', 'fee_amount', 'net_amount')
        }),
        ('Wallet Info', {
            'fields': ('sender_wallet_provider', 'sender_wallet_phone', 'receiver_wallet')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'completed_at')
        }),
        ('Additional Info', {
            'fields': ('description', 'failure_reason', 'provider_response', 'metadata'),
            'classes': ('collapse',)
        }),
    )
    
    def transaction_id_short(self, obj):
        return str(obj.transaction_id)[:8] + '...'
    transaction_id_short.short_description = 'Transaction ID'
    
    def merchant_name(self, obj):
        return obj.merchant.business_name
    merchant_name.short_description = 'Merchant'
    
    actions = ['mark_as_completed', 'mark_as_failed']
    
    def mark_as_completed(self, request, queryset):
        queryset.update(status='completed')
        self.message_user(request, f"{queryset.count()} transactions marked as completed.")
    mark_as_completed.short_description = "Mark selected transactions as completed"
    
    def mark_as_failed(self, request, queryset):
        queryset.update(status='failed')
        self.message_user(request, f"{queryset.count()} transactions marked as failed.")
    mark_as_failed.short_description = "Mark selected transactions as failed"


@admin.register(PaymentOTP)
class PaymentOTPAdmin(admin.ModelAdmin):
    list_display = ('payment_session_short', 'phone_number', 'code', 'purpose', 'is_used', 'created_at', 'is_expired_display')
    list_filter = ('purpose', 'is_used', 'created_at')
    search_fields = ('payment_session__session_id', 'phone_number', 'code')
    readonly_fields = ('created_at',)
    
    def payment_session_short(self, obj):
        return str(obj.payment_session.session_id)[:8] + '...'
    payment_session_short.short_description = 'Payment Session'
    
    def is_expired_display(self, obj):
        return obj.is_expired()
    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expired'


@admin.register(WebhookLog)
class WebhookLogAdmin(admin.ModelAdmin):
    list_display = ('payment_session_short', 'webhook_url_short', 'response_status', 'success', 'retry_count', 'sent_at')
    list_filter = ('success', 'response_status', 'sent_at')
    search_fields = ('payment_session__session_id', 'webhook_url')
    readonly_fields = ('sent_at',)
    list_select_related = ('payment_session',)
    
    fieldsets = (
        ('Webhook Info', {
            'fields': ('payment_session', 'webhook_url', 'sent_at')
        }),
        ('Request', {
            'fields': ('payload',)
        }),
        ('Response', {
            'fields': ('response_status', 'response_body', 'success', 'retry_count')
        }),
    )
    
    def payment_session_short(self, obj):
        return str(obj.payment_session.session_id)[:8] + '...'
    payment_session_short.short_description = 'Payment Session'
    
    def webhook_url_short(self, obj):
        return obj.webhook_url[:50] + '...' if len(obj.webhook_url) > 50 else obj.webhook_url
    webhook_url_short.short_description = 'Webhook URL'


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('merchant_name', 'name', 'key_prefix', 'is_active', 'is_test_mode', 'last_used_at', 'created_at')
    list_filter = ('is_active', 'is_test_mode', 'created_at', 'last_used_at')
    search_fields = ('merchant__business_name', 'name', 'key_prefix')
    readonly_fields = ('key_prefix', 'key_hash', 'last_used_at', 'created_at')
    list_select_related = ('merchant',)
    
    fieldsets = (
        ('API Key Info', {
            'fields': ('merchant', 'name', 'key_prefix', 'is_active', 'is_test_mode')
        }),
        ('Permissions', {
            'fields': ('can_create_sessions', 'can_view_transactions', 'can_refund')
        }),
        ('Usage Tracking', {
            'fields': ('last_used_at', 'created_at'),
            'classes': ('collapse',)
        }),
        ('Security', {
            'fields': ('key_hash',),
            'classes': ('collapse',)
        }),
    )
    
    def merchant_name(self, obj):
        return obj.merchant.business_name
    merchant_name.short_description = 'Merchant'
    
    actions = ['deactivate_keys', 'activate_keys']
    
    def deactivate_keys(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} API keys deactivated.")
    deactivate_keys.short_description = "Deactivate selected API keys"
    
    def activate_keys(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} API keys activated.")
    activate_keys.short_description = "Activate selected API keys"


# Custom admin site configuration
admin.site.site_header = "Nextremitly Payment Gateway Administration"
admin.site.site_title = "Nextremitly Admin"
admin.site.index_title = "Welcome to Nextremitly Payment Gateway Administration"

# Add this admin class to your admin.py
@admin.register(WalletVerificationOTP)
class WalletVerificationOTPAdmin(admin.ModelAdmin):
    list_display = ('merchant_name', 'provider_name', 'wallet_id', 'wallet_name', 'verification_status', 'is_used', 'created_at', 'is_expired_display')
    list_filter = ('verification_status', 'wallet_provider', 'is_used', 'created_at')
    search_fields = ('merchant__business_name', 'wallet_id', 'wallet_name', 'code')
    readonly_fields = ('created_at',)
    list_select_related = ('merchant', 'wallet_provider')
    
    fieldsets = (
        ('Verification Info', {
            'fields': ('merchant', 'wallet_provider', 'wallet_id', 'wallet_name')
        }),
        ('Wallet Settings', {
            'fields': ('is_active', 'is_primary', 'verification_status')
        }),
        ('OTP Details', {
            'fields': ('code', 'purpose', 'is_used', 'created_at')
        }),
    )
    
    def merchant_name(self, obj):
        return obj.merchant.business_name
    merchant_name.short_description = 'Merchant'
    
    def provider_name(self, obj):
        return obj.wallet_provider.display_name
    provider_name.short_description = 'Provider'
    
    def is_expired_display(self, obj):
        return obj.is_expired()
    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expired'