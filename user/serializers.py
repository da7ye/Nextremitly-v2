# serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import CustUser, Buyer, Merchant, WalletVerificationOTP
import random
import string


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = CustUser
        fields = ['email', 'nom_complet', 'adrese', 'numero_telephone', 'password', 'password_confirm']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs
    
    def validate_email(self, value):
        if CustUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email already exists.")
        return value


class BuyerRegistrationSerializer(UserRegistrationSerializer):
    preferred_payment_method = serializers.CharField(max_length=50, required=False)
    date_of_birth = serializers.DateField(required=False)
    
    class Meta:
        model = Buyer
        fields = ['email', 'nom_complet', 'adrese', 'numero_telephone', 'password', 
                 'password_confirm', 'preferred_payment_method', 'date_of_birth']
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        buyer = Buyer(**validated_data)
        buyer.set_password(password)
        buyer.user_type = 'buyer'
        buyer.save()
        return buyer


class MerchantRegistrationSerializer(UserRegistrationSerializer):
    business_name = serializers.CharField(max_length=255, required=False)
    website = serializers.URLField(required=False)
    category = serializers.CharField(max_length=100)
    bank_account_number = serializers.CharField(max_length=30)
    
    class Meta:
        model = Merchant
        fields = ['email', 'nom_complet', 'adrese', 'numero_telephone', 'password',
                 'password_confirm', 'business_name', 'website', 'category', 'bank_account_number']
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        merchant = Merchant(**validated_data)
        merchant.set_password(password)
        merchant.user_type = 'merchant'
        merchant.save()
        return merchant


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            user = authenticate(username=email, password=password)
            if not user:
                raise serializers.ValidationError('Invalid email or password.')
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled.')
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include email and password.')
        
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustUser
        fields = ['id', 'email', 'nom_complet', 'adrese', 'numero_telephone', 
                 'user_type', 'is_verified', 'date_verified', 'date_joined']
        read_only_fields = ['id', 'email', 'user_type', 'is_verified', 'date_verified', 'date_joined']


class BuyerProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Buyer
        fields = ['id', 'email', 'nom_complet', 'adrese', 'numero_telephone', 
                 'preferred_payment_method', 'date_of_birth', 'phone_verified',
                 'is_verified', 'date_verified', 'date_joined']
        read_only_fields = ['id', 'email', 'phone_verified', 'is_verified', 'date_verified', 'date_joined']


class MerchantProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchant
        fields = ['id', 'email', 'nom_complet', 'adrese', 'numero_telephone',
                 'business_name', 'website', 'category', 'bank_account_number',
                 'verification_status', 'activation_status', 'is_verified', 
                 'date_verified', 'date_joined']
        read_only_fields = ['id', 'email', 'verification_status', 'activation_status', 
                           'is_verified', 'date_verified', 'date_joined']


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match.")
        return attrs
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        if not CustUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    purpose = serializers.ChoiceField(choices=[
        ('verification', 'Account Verification'),
        ('password_reset', 'Password Reset'),
    ], default='verification')



#! Nextremitly Serializers:


from rest_framework import serializers
from .models import (
    WalletProvider, MerchantWallet, PaymentSession, 
    Transaction, PaymentOTP, APIKey
)
import uuid
from decimal import Decimal


# class WalletProviderSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = WalletProvider
#         fields = ['id', 'name', 'display_name', 'logo_url', 'is_active', 'supports_otp']

class WalletProviderSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()
    
    class Meta:
        model = WalletProvider
        fields = ['id', 'name', 'display_name', 'logo_url', 'image', 'image_url', 'is_active', 'supports_otp']
    
    def get_image_url(self, obj):
        """Get the full URL for the image"""
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None

class MerchantWalletSerializer(serializers.ModelSerializer):
    provider = WalletProviderSerializer(read_only=True)
    provider_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = MerchantWallet
        fields = [
            'id', 'provider', 'provider_id', 'wallet_id', 'wallet_name', 
            'is_active', 'is_primary', 'created_at'
        ]
        read_only_fields = ['created_at']
    
    def validate(self, attrs):
        # Ensure only one primary wallet per merchant
        if attrs.get('is_primary'):
            merchant = self.context['request'].user
            if MerchantWallet.objects.filter(merchant=merchant, is_primary=True).exclude(id=self.instance.id if self.instance else None).exists():
                raise serializers.ValidationError("Only one wallet can be set as primary")
        return attrs


class PaymentSessionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating payment sessions via API"""
    
    class Meta:
        model = PaymentSession
        fields = [
            'amount', 'currency', 'description', 'customer_email', 
            'customer_phone', 'success_url', 'cancel_url', 'webhook_url', 'metadata'
        ]
    
    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than zero")
        if value > Decimal('1000000'):  # 1 million limit
            raise serializers.ValidationError("Amount exceeds maximum limit")
        return value
    
    def validate(self, attrs):
        # Validate URLs
        for url_field in ['success_url', 'cancel_url', 'webhook_url']:
            url = attrs.get(url_field)
            if url and not url.startswith(('http://', 'https://')):
                raise serializers.ValidationError(f"{url_field} must be a valid URL")
        return attrs


class PaymentSessionSerializer(serializers.ModelSerializer):
    """Serializer for displaying payment session details"""
    merchant_name = serializers.CharField(source='merchant.business_name', read_only=True)
    selected_wallet = MerchantWalletSerializer(read_only=True)
    is_expired = serializers.SerializerMethodField()
    
    class Meta:
        model = PaymentSession
        fields = [
            'session_id', 'merchant_name', 'amount', 'currency', 'description',
            'customer_email', 'customer_phone', 'status', 'selected_wallet',
            'customer_wallet_phone', 'created_at', 'expires_at', 'is_expired'
        ]
    
    def get_is_expired(self, obj):
        return obj.is_expired()


class PaymentSessionUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating payment session during payment flow"""
    
    class Meta:
        model = PaymentSession
        fields = ['status', 'selected_wallet', 'customer_wallet_phone']
    
    def validate_status(self, value):
        # Validate status transitions
        current_status = self.instance.status if self.instance else None
        
        valid_transitions = {
            'pending': ['authenticated', 'cancelled', 'expired'],
            'authenticated': ['wallet_selected', 'cancelled'],
            'wallet_selected': ['otp_sent', 'cancelled'],
            'otp_sent': ['processing', 'cancelled'],
            'processing': ['completed', 'failed'],
            'completed': [],  # Final state
            'failed': ['pending'],  # Can retry
            'cancelled': [],  # Final state
            'expired': [],  # Final state
        }
        
        if current_status and value not in valid_transitions.get(current_status, []):
            raise serializers.ValidationError(f"Cannot transition from {current_status} to {value}")
        
        return value


class TransactionSerializer(serializers.ModelSerializer):
    sender_name = serializers.CharField(source='sender.nom_complet', read_only=True)
    receiver_name = serializers.CharField(source='receiver.nom_complet', read_only=True)
    merchant_name = serializers.CharField(source='merchant.business_name', read_only=True)
    sender_wallet_provider_name = serializers.CharField(source='sender_wallet_provider.display_name', read_only=True)
    receiver_wallet_name = serializers.CharField(source='receiver_wallet.wallet_name', read_only=True)
    
    class Meta:
        model = Transaction
        fields = [
            'transaction_id', 'transaction_type', 'amount', 'currency', 'fee_amount', 
            'net_amount', 'status', 'description', 'sender_name', 'receiver_name',
            'merchant_name', 'sender_wallet_provider_name', 'receiver_wallet_name',
            'sender_wallet_phone', 'external_transaction_id', 'created_at', 
            'completed_at', 'failure_reason'
        ]
        read_only_fields = [
            'transaction_id', 'net_amount', 'external_transaction_id', 
            'created_at', 'completed_at'
        ]


class PaymentOTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentOTP
        fields = ['phone_number', 'created_at', 'is_expired']
    
    def get_is_expired(self, obj):
        return obj.is_expired()


class PaymentInitiateSerializer(serializers.Serializer):
    """Serializer for initiating payment after wallet selection"""
    phone_number = serializers.CharField(max_length=20)
    
    def validate_phone_number(self, value):
        # Basic phone number validation
        import re
        if not re.match(r'^\+?[1-9]\d{1,14}$', value.replace(' ', '')):
            raise serializers.ValidationError("Invalid phone number format")
        return value


class PaymentConfirmSerializer(serializers.Serializer):
    """Serializer for confirming payment with OTP"""
    otp_code = serializers.CharField(max_length=6)
    phone_number = serializers.CharField(max_length=20)


class APIKeySerializer(serializers.ModelSerializer):
    key = serializers.CharField(read_only=True)
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'key_prefix', 'key', 'is_active', 'is_test_mode',
            'can_create_sessions', 'can_view_transactions', 'can_refund',
            'last_used_at', 'created_at'
        ]
        read_only_fields = ['key_prefix', 'key', 'last_used_at', 'created_at']


# Dashboard serializers for merchant analytics
class MerchantDashboardSerializer(serializers.Serializer):
    """Serializer for merchant dashboard data"""
    total_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)
    daily_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)
    pending_amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    active_wallets_count = serializers.IntegerField()
    total_transactions = serializers.IntegerField()
    successful_transactions = serializers.IntegerField()
    recent_transactions = TransactionSerializer(many=True)


class BuyerDashboardSerializer(serializers.Serializer):
    """Serializer for buyer dashboard data"""
    total_spent = serializers.DecimalField(max_digits=12, decimal_places=2)
    total_received = serializers.DecimalField(max_digits=12, decimal_places=2)
    pending_transactions = serializers.IntegerField()
    completed_transactions = serializers.IntegerField()
    recent_transactions = TransactionSerializer(many=True)


# Integration serializers for documentation
class WebhookPayloadSerializer(serializers.Serializer):
    """Serializer for webhook payload structure"""
    session_id = serializers.UUIDField()
    status = serializers.CharField()
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    currency = serializers.CharField()
    transaction_id = serializers.UUIDField()
    external_transaction_id = serializers.CharField()
    completed_at = serializers.DateTimeField()
    metadata = serializers.JSONField()


class PaymentWidgetConfigSerializer(serializers.Serializer):
    """Serializer for payment widget configuration"""
    api_key = serializers.CharField()
    session_id = serializers.UUIDField()
    environment = serializers.ChoiceField(choices=['test', 'live'])
    theme = serializers.ChoiceField(choices=['light', 'dark'], default='light')
    language = serializers.ChoiceField(choices=['en', 'fr', 'ar'], default='en')


# Add these serializers to your serializers.py file

class WalletVerificationRequestSerializer(serializers.Serializer):
    """Serializer for initiating wallet verification"""
    provider_id = serializers.IntegerField()
    wallet_id = serializers.CharField(max_length=100)
    wallet_name = serializers.CharField(max_length=100)
    is_active = serializers.BooleanField(default=True)
    is_primary = serializers.BooleanField(default=False)
    
    def validate_wallet_id(self, value):
        """Basic phone number validation"""
        import re
        # Remove spaces and validate format
        clean_value = value.replace(' ', '')
        if not re.match(r'^\+?[1-9]\d{1,14}$', clean_value):
            raise serializers.ValidationError("Invalid phone number format")
        return clean_value


class WalletVerificationConfirmSerializer(serializers.Serializer):
    """Serializer for confirming wallet verification with OTP"""
    otp_code = serializers.CharField(max_length=6)
    verification_id = serializers.UUIDField()


class WalletVerificationOTPSerializer(serializers.ModelSerializer):
    """Serializer for wallet verification OTP details"""
    provider_name = serializers.CharField(source='wallet_provider.display_name', read_only=True)
    
    class Meta:
        model = WalletVerificationOTP
        fields = [
            'id', 'wallet_id', 'wallet_name', 'provider_name', 
            'verification_status', 'created_at', 'is_expired'
        ]
    
    def get_is_expired(self, obj):
        return obj.is_expired()
    


# from .models import QRCode, QRPaymentSession, QRPaymentOTP, WalletProvider

# class QRCodeSerializer(serializers.ModelSerializer):
#     qr_url = serializers.SerializerMethodField()
#     qr_image = serializers.SerializerMethodField()

#     class Meta:
#         model = QRCode
#         fields = [
#             'id', 'name', 'description', 'qr_type', 'status',
#             'created_at', 'scans_count', 'total_revenue',
#             'qr_url', 'fixed_amount', 'qr_image'
#         ]
#         read_only_fields = ['id', 'created_at', 'scans_count', 'total_revenue']

#     def get_qr_url(self, obj):
#         frontend_url = getattr(settings, "FRONTEND_BASE_URL", "http://localhost:5173")
#         return f"{frontend_url}/public/qr/{obj.id}"

#     def get_qr_image(self, obj):
#         qr_url = self.get_qr_url(obj)
#         qr_img = qrcode.make(qr_url)
#         buffer = BytesIO()
#         qr_img.save(buffer, format="PNG")
#         img_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
#         return f"data:image/png;base64,{img_str}"
    
#     # Dans serializers.py - QRCodeSerializer

#     def validate(self, attrs):
#          # Validation spécifique pour QR statique
#         if attrs.get('qr_type') == 'static':
#             fixed_amount = attrs.get('fixed_amount')
            
#             # ✅ Gérer le cas où fixed_amount est None, vide ou 0
#             if not fixed_amount or fixed_amount == '' or fixed_amount == 0:
#                 raise serializers.ValidationError({
#                     'fixed_amount': 'Le montant fixe est requis pour un QR code statique'
#                 })
            
#             # Convertir en Decimal si c'est une chaîne
#             try:
#                 from decimal import Decimal
#                 amount = Decimal(str(fixed_amount))
#             except:
#                 raise serializers.ValidationError({
#                     'fixed_amount': 'Le montant doit être un nombre valide'
#                 })
            
#             if amount <= 0:
#                 raise serializers.ValidationError({
#                     'fixed_amount': 'Le montant doit être supérieur à 0'
#                 })
#             if amount > 1000000:
#                 raise serializers.ValidationError({
#                     'fixed_amount': 'Le montant ne peut pas dépasser 1 000 000 MRU'
#                 })
            
#             # ✅ Stocker le montant converti
#             attrs['fixed_amount'] = amount
#         else:
#         # Pour QR dynamique, s'assurer que fixed_amount est null
#           attrs['fixed_amount'] = None
    
#         return attrs
    
#     def create(self, validated_data):
#         user = self.context['request'].user
#         try:
#             merchant = Merchant.objects.get(id=user.id)
#             validated_data['merchant'] = merchant
            
#             print(f" Création QR pour merchant: {merchant.business_name}")
#             print(f" Type: {validated_data.get('qr_type')}")
#             print(f" Montant fixe: {validated_data.get('fixed_amount')}")
            
#             instance = QRCode.objects.create(
#                 merchant=merchant,
#                 name=validated_data['name'],
#                 qr_type=validated_data['qr_type'],
#                 description=validated_data.get('description', ''),
#                 fixed_amount=validated_data.get('fixed_amount'),
#                 status='active',
#                 scans_count=0,
#                 total_revenue=0
#             )
            
#             print(f" QR créé avec ID: {instance.id}")
#             return instance
            
#         except Merchant.DoesNotExist:
#             raise serializers.ValidationError("L'utilisateur doit être un merchant pour créer un QR Code")

# class QRCodeStatsSerializer(serializers.Serializer):
#     total_qrs = serializers.IntegerField()
#     active_qrs = serializers.IntegerField()
#     total_scans = serializers.IntegerField()
#     total_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)

# class QRPaymentInitiateSerializer(serializers.Serializer):
#     amount = serializers.DecimalField(max_digits=12, decimal_places=2, required=False)  # Optionnel pour QR statique
#     wallet_type = serializers.CharField(max_length=50)
#     phone_number = serializers.CharField(max_length=20)
#     customer_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    
#     def validate(self, attrs):
#         # Le montant sera validé dans la vue selon le type de QR
#         return attrs
    
#     def validate_wallet_type(self, value):
#         if not WalletProvider.objects.filter(name=value, is_active=True).exists():
#             raise serializers.ValidationError("Portefeuille non supporté")
#         return value
    
#     def validate_phone_number(self, value):
#         import re
#         clean_value = value.replace(' ', '').replace('+222', '')
#         if not re.match(r'^[2-4]\d{7}$', clean_value):
#             raise serializers.ValidationError("Numéro de téléphone invalide")
#         return clean_value
# class QRPaymentSessionSerializer(serializers.ModelSerializer):
#     qr_code_name = serializers.CharField(source='qr_code.name', read_only=True)
#     merchant_name = serializers.CharField(source='merchant.business_name', read_only=True)
    
#     class Meta:
#         model = QRPaymentSession
#         fields = [
#             'session_id', 'amount', 'currency', 'customer_phone', 'customer_wallet_phone',
#             'status', 'created_at', 'completed_at', 'qr_code_name', 'merchant_name'
#         ]

# class QRPaymentOTPVerifySerializer(serializers.Serializer):
#     otp_code = serializers.CharField(max_length=6)
    
#     def validate_otp_code(self, value):
#         if len(value) not in [4, 6]:  # Support both 4 and 6 digit OTPs
#             raise serializers.ValidationError("Le code OTP doit contenir 4 ou 6 chiffres")
#         if not value.isdigit():
#             raise serializers.ValidationError("Le code OTP ne doit contenir que des chiffres")
#         return value
#     otp_code = serializers.CharField(max_length=6)
    
#     def validate_otp_code(self, value):
#         if len(value) != 4:
#             raise serializers.ValidationError("Le code OTP doit contenir 4 chiffres")
#         if not value.isdigit():
#             raise serializers.ValidationError("Le code OTP ne doit contenir que des chiffres")
#         return value


# qr_serializers.py - Refactored QR Code Serializers
from decimal import Decimal
import random
import string

class QRCodeSerializer(serializers.Serializer):
    """QR Code Serializer"""
    
    id = serializers.CharField(read_only=True)
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=1000
    )
    qr_type = serializers.ChoiceField(choices=['static', 'dynamic'])
    fixed_amount = serializers.DecimalField(
        max_digits=12,
        decimal_places=2,
        required=False,
        allow_null=True
    )
    status = serializers.CharField(read_only=True)
    scans_count = serializers.IntegerField(read_only=True)
    total_revenue = serializers.DecimalField(
        max_digits=12,
        decimal_places=2,
        read_only=True
    )
    is_valid = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True)
    
    def get_is_valid(self, obj):
        """Check if QR code is valid"""
        return obj.is_valid if hasattr(obj, 'is_valid') else True
    
    def validate_name(self, value):
        """Validate QR code name"""
        if not value or not value.strip():
            raise serializers.ValidationError("Name is required")
        if len(value) > 255:
            raise serializers.ValidationError("Name must be less than 255 characters")
        return value.strip()
    
    def validate_fixed_amount(self, value):
        """Validate fixed amount"""
        if value is not None and value <= 0:
            raise serializers.ValidationError("Amount must be greater than 0")
        return value
    
    def validate(self, data):
        """Validate QR code data"""
        if data.get('qr_type') == 'static' and not data.get('fixed_amount'):
            raise serializers.ValidationError(
                "Fixed amount is required for static QR codes"
            )
        return data
    
    def create(self, validated_data):
        """Create QR code"""
        from .models import QRCode
        merchant = self.context.get('merchant')
        if not merchant:
            raise serializers.ValidationError("Merchant information is required")
        
        qr_code = QRCode.objects.create(
            merchant=merchant,
            name=validated_data['name'],
            description=validated_data.get('description', ''),
            qr_type=validated_data['qr_type'],
            fixed_amount=validated_data.get('fixed_amount'),
            status='active',
            scans_count=0,
            total_revenue=0
        )
        return qr_code


class QRPaymentSessionSerializer(serializers.Serializer):
    """QR Payment Session Serializer"""
    
    session_id = serializers.UUIDField(read_only=True)
    qr_id = serializers.CharField(source='qr_code.id', read_only=True)
    merchant_name = serializers.CharField(
        source='merchant.business_name',
        read_only=True
    )
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    currency = serializers.CharField(default='MRU')
    customer_phone = serializers.CharField(max_length=20)
    customer_wallet_type = serializers.CharField(required=False)
    status = serializers.CharField(read_only=True)
    is_expired = serializers.SerializerMethodField()
    expires_at = serializers.DateTimeField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    
    def get_is_expired(self, obj):
        return obj.is_expired if hasattr(obj, 'is_expired') else False
    
    def validate_amount(self, value):
        """Validate payment amount"""
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than 0")
        if value > 1000000:
            raise serializers.ValidationError("Amount cannot exceed 1,000,000 MRU")
        return value
    
    def validate_customer_phone(self, value):
        """Validate phone number"""
        clean_phone = value.replace('+', '').replace(' ', '')
        if not clean_phone.isdigit():
            raise serializers.ValidationError("Phone number must contain only digits")
        if len(clean_phone) < 8:
            raise serializers.ValidationError("Phone number must be at least 8 digits")
        return clean_phone[-8:]  # Return last 8 digits


class QRPaymentInitiateSerializer(serializers.Serializer):
    """Initiate QR Payment Serializer"""
    
    amount = serializers.DecimalField(
        max_digits=12,
        decimal_places=2,
        required=False,
        allow_null=True
    )
    phone_number = serializers.CharField(max_length=20)
    wallet_type = serializers.CharField(max_length=50)
    
    def validate_phone_number(self, value):
        """Validate phone number"""
        clean_phone = value.replace('+', '').replace(' ', '')
        if not clean_phone.isdigit():
            raise serializers.ValidationError("Phone number must contain only digits")
        if len(clean_phone) < 8:
            raise serializers.ValidationError("Phone number must be at least 8 digits")
        return clean_phone[-8:]  # Return last 8 digits


class QRPaymentVerifySerializer(serializers.Serializer):
    """Verify QR Payment OTP Serializer"""
    
    otp_code = serializers.CharField(
        max_length=6,
        min_length=4,
        help_text="OTP code (4-6 digits)"
    )
    
    def validate_otp_code(self, value):
        """Validate OTP code"""
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits")
        return value


class QRCodeStatsSerializer(serializers.Serializer):
    """QR Code Statistics Serializer"""
    
    total_qrs = serializers.IntegerField()
    active_qrs = serializers.IntegerField()
    total_scans = serializers.IntegerField()
    total_revenue = serializers.DecimalField(max_digits=12, decimal_places=2)


class OTPGenerator:
    """Utility class for OTP generation"""
    
    @staticmethod
    def generate(length=6):
        """Generate random OTP"""
        return ''.join(random.choices(string.digits, k=length))
    
    @staticmethod
    def generate_short(length=4):
        """Generate short OTP (4 digits)"""
        return ''.join(random.choices(string.digits, k=length))


class QRPaymentTransactionSerializer(serializers.Serializer):
    """QR Payment Transaction Serializer"""
    
    transaction_id = serializers.UUIDField(read_only=True)
    session_id = serializers.UUIDField(read_only=True)
    merchant_name = serializers.CharField(read_only=True)
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)
    currency = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    completed_at = serializers.DateTimeField(read_only=True)