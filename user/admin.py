# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustUser, Buyer, Merchant, OTP_User


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