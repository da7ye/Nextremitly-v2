import base64
from io import BytesIO
from django.db import models
from django.contrib.auth.base_user import  BaseUserManager
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone
import qrcode



class CustomAccountManager(BaseUserManager):
    def create_user(self, email,  password, **other_fields):
        user = self.model(email=email, **other_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **other_fields):
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError(
                'Superuser must be assigned to is_staff=True.')
        if other_fields.get('is_superuser') is not True:
            raise ValueError(
                'Superuser must be assigned to is_superuser=True.')

        return self.create_user(email, password, **other_fields)
    
class CustUser(AbstractUser):
    USER_TYPE_CHOICES = [
        ('buyer', 'Buyer'),
        ('merchant', 'Merchant'),
        # ('admin', 'Administrator'),
    ]
    
    email = models.EmailField(max_length=255, unique=True)
    nom_complet = models.CharField(max_length=100, default='')
    adrese = models.CharField(max_length=255, default='')
    numero_telephone = models.CharField(max_length=20, default='', null=True, blank=True)
    username = models.CharField(max_length=255, default="", blank=True)
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='buyer')
    is_verified = models.BooleanField(default=False)
    date_verified = models.DateTimeField(null=True, blank=True)
    
    objects = CustomAccountManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # Unique related names for groups and permissions
    groups = models.ManyToManyField(Group, related_name='custom_user_groups')
    user_permissions = models.ManyToManyField(Permission, related_name='custom_user_permissions')

    def __str__(self):
        return self.email or 'No Email'

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"



class Buyer(CustUser):
    # Buyer-specific fields
    preferred_payment_method = models.CharField(max_length=50, blank=True, null=True)
    date_of_birth = models.DateField(null=True, blank=True)
    phone_verified = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Buyer: {self.email or self.username}"

    class Meta:
        verbose_name = "Buyer"
        verbose_name_plural = "Buyers"

    def save(self, *args, **kwargs):
        self.user_type = 'buyer'
        if self.password and not self.password.startswith('pbkdf2_sha256'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

class Merchant(CustUser):
    # Merchant-specific fields
    business_name = models.CharField(max_length=255, blank=True)
    website = models.URLField(blank=True)
    category = models.CharField(max_length=100)
    verification_status = models.BooleanField(default=False)
    activation_status = models.BooleanField(default=True)
    bank_account_number = models.CharField(max_length=30)
    # business_registration_number = models.CharField(max_length=50, blank=True)
    # tax_id = models.CharField(max_length=50, blank=True)
    # monthly_transaction_limit = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    
    def __str__(self):
        return f"Merchant: {self.business_name or self.email}"

    class Meta:
        verbose_name = "Merchant"
        verbose_name_plural = "Merchants"
    
    def save(self, *args, **kwargs):
        self.user_type = 'merchant'
        if self.password and not self.password.startswith('pbkdf2_sha256'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)



class OTPBase(models.Model):
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    purpose = models.CharField(max_length=50, choices=[
        ('verification', 'Account Verification'),
        ('password_reset', 'Password Reset'),
        ('transaction', 'Transaction Verification'),
        ('login', 'Login Verification')
    ], default='verification')

    OTP_EXPIRY_SECONDS = 300  # 5 minutes

    class Meta:
        abstract = True

    def is_expired(self):
        now = timezone.now()
        expiry_time = self.created_at + timezone.timedelta(seconds=self.OTP_EXPIRY_SECONDS)
        return now > expiry_time


class OTP_User(OTPBase):
    user = models.ForeignKey(CustUser, on_delete=models.CASCADE, related_name='otps')
    
    def __str__(self):
        return f"OTP for {self.user.email} - {self.purpose}"

    class Meta:
        verbose_name = "User OTP"
        verbose_name_plural = "User OTPs"


# class Administrator(CustUser):
#     # Administrator-specific fields
#     role = models.CharField(max_length=100, default="Platform Admin")
#     department = models.CharField(max_length=100, blank=True)
#     permissions_level = models.CharField(max_length=20, choices=[
#         ('low', 'Low'),
#         ('medium', 'Medium'),
#         ('high', 'High'),
#         ('super', 'Super Admin')
#     ], default='medium')
    
#     def __str__(self):
#         return f"Admin: {self.email}"

#     class Meta:
#         verbose_name = "Administrator"
#         verbose_name_plural = "Administrators"
    
#     def save(self, *args, **kwargs):
#         self.user_type = 'admin'
#         self.is_staff = True
#         if self.permissions_level == 'super':
#             self.is_superuser = True
#         if self.password and not self.password.startswith('pbkdf2_sha256'):
#             self.password = make_password(self.password)
#         super().save(*args, **kwargs)



# Nextremitly Models:

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid
import secrets
import string

class WalletProvider(models.Model):
    """Available wallet providers/banks"""
    PROVIDER_CHOICES = [
        ('bankily', 'Bankily'),
        ('sedad', 'Sedad'),
        ('bimbank', 'Bimbank'),
        ('paypal', 'PayPal'),
        ('stripe', 'Stripe'),
        ('mtn_mobile_money', 'MTN Mobile Money'),
    ]
    
    name = models.CharField(max_length=50, choices=PROVIDER_CHOICES, unique=True)
    display_name = models.CharField(max_length=100)
    logo_url = models.URLField(blank=True)
    image = models.ImageField(
        upload_to='wallet_providers/',
        null=True,
        blank=True,
        help_text="Provider logo or icon image"
    )
    is_active = models.BooleanField(default=True)
    api_endpoint = models.URLField(help_text="Bank's API endpoint for transactions")
    supports_otp = models.BooleanField(default=True)
    
    def __str__(self):
        return self.display_name
    
    class Meta:
        verbose_name = "Wallet Provider"
        verbose_name_plural = "Wallet Providers"

class MerchantWallet(models.Model):
    """Merchant's configured wallets for receiving payments"""
    merchant = models.ForeignKey('Merchant', on_delete=models.CASCADE, related_name='wallets')
    provider = models.ForeignKey(WalletProvider, on_delete=models.CASCADE)
    wallet_id = models.CharField(max_length=100, help_text="Merchant's wallet ID/phone number with this provider")
    wallet_name = models.CharField(max_length=100, help_text="Custom name for this wallet")
    is_active = models.BooleanField(default=True)
    is_primary = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['merchant', 'provider', 'wallet_id']
        verbose_name = "Merchant Wallet"
        verbose_name_plural = "Merchant Wallets"
    
    def __str__(self):
        return f"{self.merchant.business_name} - {self.provider.display_name}"


class PaymentSession(models.Model):
    """Payment session created by ecommerce when user proceeds to checkout"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('authenticated', 'User Authenticated'),
        ('wallet_selected', 'Wallet Selected'),
        ('otp_sent', 'OTP Sent'),
        ('processing', 'Processing Payment'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('expired', 'Expired'),
    ]
    
    session_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    merchant = models.ForeignKey('Merchant', on_delete=models.CASCADE, related_name='payment_sessions')
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='MRU')  # Mauritanian Ouguiya
    description = models.TextField(blank=True)
    customer_email = models.EmailField(blank=True)
    customer_phone = models.CharField(max_length=20, blank=True)
    
    # Ecommerce callback URLs
    success_url = models.URLField(help_text="URL to redirect after successful payment")
    cancel_url = models.URLField(help_text="URL to redirect after cancelled payment")
    webhook_url = models.URLField(blank=True, help_text="URL to receive payment status updates")
    
    # Payment flow tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    authenticated_user = models.ForeignKey(CustUser, on_delete=models.SET_NULL, null=True, blank=True)
    selected_wallet = models.ForeignKey(MerchantWallet, on_delete=models.SET_NULL, null=True, blank=True)
    customer_wallet_phone = models.CharField(max_length=20, blank=True, help_text="Customer's wallet phone number")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    metadata = models.JSONField(default=dict, blank=True, help_text="Additional data from ecommerce")
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            # Session expires in 30 minutes
            self.expires_at = timezone.now() + timezone.timedelta(minutes=30)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"Payment {self.session_id} - {self.merchant.business_name} - {self.amount} {self.currency}"
    
    class Meta:
        verbose_name = "Payment Session"
        verbose_name_plural = "Payment Sessions"


class Transaction(models.Model):
    """Individual transaction record"""
    TRANSACTION_TYPES = [
        ('payment', 'Payment'),
        ('refund', 'Refund'),
        ('transfer', 'Transfer'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
    ]
    
    transaction_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    payment_session = models.ForeignKey(PaymentSession, on_delete=models.CASCADE, related_name='transactions', null=True, blank=True)
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES, default='payment')
    
    # Parties involved
    sender = models.ForeignKey(CustUser, on_delete=models.SET_NULL, null=True, related_name='sent_transactions')
    receiver = models.ForeignKey(CustUser, on_delete=models.SET_NULL, null=True, related_name='received_transactions')
    merchant = models.ForeignKey('Merchant', on_delete=models.CASCADE, related_name='transactions')
    
    # Transaction details
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='MRU')
    fee_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    net_amount = models.DecimalField(max_digits=12, decimal_places=2)  # amount - fee
    
    # Wallet information
    sender_wallet_provider = models.ForeignKey(WalletProvider, on_delete=models.SET_NULL, null=True, related_name='sender_transactions')
    sender_wallet_phone = models.CharField(max_length=20)
    receiver_wallet = models.ForeignKey(MerchantWallet, on_delete=models.SET_NULL, null=True)
    
    # Bank/Provider response
    external_transaction_id = models.CharField(max_length=255, blank=True, help_text="Transaction ID from bank/provider")
    provider_response = models.JSONField(default=dict, blank=True)
    
    # Status tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    failure_reason = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    description = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    def save(self, *args, **kwargs):
        if not self.net_amount:
            self.net_amount = self.amount - self.fee_amount
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Transaction {self.transaction_id} - {self.amount} {self.currency}"
    
    class Meta:
        verbose_name = "Transaction"
        verbose_name_plural = "Transactions"
        ordering = ['-created_at']


class PaymentOTP(OTPBase):
    """OTP for payment transactions"""
    payment_session = models.ForeignKey(PaymentSession, on_delete=models.CASCADE, related_name='otps')
    phone_number = models.CharField(max_length=20)
    
    def __str__(self):
        return f"Payment OTP for session {self.payment_session.session_id}"
    
    class Meta:
        verbose_name = "Payment OTP"
        verbose_name_plural = "Payment OTPs"


class WebhookLog(models.Model):
    """Log of webhook calls to ecommerce"""
    payment_session = models.ForeignKey(PaymentSession, on_delete=models.CASCADE, related_name='webhook_logs')
    webhook_url = models.URLField()
    payload = models.JSONField()
    response_status = models.IntegerField(null=True)
    response_body = models.TextField(blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    retry_count = models.IntegerField(default=0)
    
    class Meta:
        verbose_name = "Webhook Log"
        verbose_name_plural = "Webhook Logs"


class APIKey(models.Model):
    """API keys for merchants to integrate with the payment gateway"""
    merchant = models.ForeignKey('Merchant', on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=100, help_text="Descriptive name for this API key")
    key_prefix = models.CharField(max_length=10, editable=False)
    key_hash = models.CharField(max_length=255, editable=False)
    is_active = models.BooleanField(default=True)
    is_test_mode = models.BooleanField(default=True, help_text="Whether this key is for testing")
    
    # Permissions
    can_create_sessions = models.BooleanField(default=True)
    can_view_transactions = models.BooleanField(default=True)
    can_refund = models.BooleanField(default=False)
    
    # Usage tracking
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
        
        # In your models.py, update the APIKey model's generate_key method:

    def generate_key(self):
        """Generate a new API key"""
        import secrets
        import string
        from django.contrib.auth.hashers import make_password
        
        # Generate a random key
        alphabet = string.ascii_letters + string.digits
        key = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        # Store prefix for display
        self.key_prefix = key[:8]
        
        # Hash the full key for storage
        self.key_hash = make_password(key)
        
        # Save the updated instance
        self.save()
        
        # Return the full key with prefix
        full_key = f"nxt_{'test' if self.is_test_mode else 'live'}_{key}"
        
        print(f"Full generated key: {full_key}")  # Debug print
        return full_key

    def check_key(self, provided_key):
        """Check if provided key matches this API key"""
        from django.contrib.auth.hashers import check_password
        
        print(f"Checking key: {provided_key}")  # Debug print
        print(f"Expected prefix: nxt_{'test' if self.is_test_mode else 'live'}_")  # Debug print
        
        # Extract the key part after the prefix
        if provided_key.startswith(f"nxt_{'test' if self.is_test_mode else 'live'}_"):
            key_part = provided_key.split('_', 2)[-1]  # Get the part after "nxt_test_" or "nxt_live_"
            print(f"Extracted key part: {key_part}")  # Debug print
            return check_password(key_part, self.key_hash)
        
        return False
    
    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"



# Add this class to your models.py file after the PaymentOTP class

class WalletVerificationOTP(OTPBase):
    """OTP for wallet verification"""
    merchant = models.ForeignKey('Merchant', on_delete=models.CASCADE, related_name='wallet_otps')
    wallet_provider = models.ForeignKey(WalletProvider, on_delete=models.CASCADE)
    wallet_id = models.CharField(max_length=100, help_text="Wallet ID/phone number being verified")
    wallet_name = models.CharField(max_length=100, help_text="Custom name for this wallet")
    is_active = models.BooleanField(default=True)
    is_primary = models.BooleanField(default=False)
    verification_status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending Verification'),
        ('verified', 'Verified'),
        ('failed', 'Verification Failed'),
    ], default='pending')
    
    def __str__(self):
        return f"Wallet OTP for {self.merchant.business_name} - {self.wallet_provider.display_name}"

    class Meta:
        verbose_name = "Wallet Verification OTP"
        verbose_name_plural = "Wallet Verification OTPs"





# class QRCode(models.Model):
#     """QR Code pour paiements directs en magasin"""
#     qr_type = models.CharField(max_length=20, choices=[
#         ('static', 'Statique'),
#         ('dynamic', 'Dynamique')
#     ])
    
#     STATUS_CHOICES = [
#         ('active', 'Actif'),
#         ('inactive', 'Inactif'),
#         ('expired', 'Expiré'),
#     ]
#     fixed_amount = models.DecimalField(
#         max_digits=12, 
#         decimal_places=2, 
#         null=True, 
#         blank=True,
       
#     )
#     id = models.CharField(max_length=50, primary_key=True, unique=True)
#     merchant = models.ForeignKey(Merchant, on_delete=models.CASCADE, related_name='qr_codes')
#     name = models.CharField(max_length=100)
#     description = models.TextField(blank=True, null=True)
#     status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
#     expires_at = models.DateTimeField(null=True, blank=True)
#     scans_count = models.IntegerField(default=0)
#     total_revenue = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    
#     class Meta:
#         db_table = 'nextremitly_qrcodes'
#         ordering = ['-created_at']
#         verbose_name = "QR Code"
#         verbose_name_plural = "QR Codes"
    
#     def __str__(self):
#         return f"{self.name} ({self.id})"
    
#     def save(self, *args, **kwargs):
#     # Génération d’un ID unique si non défini
#         if not self.id:
#             self.id = f"qr_{uuid.uuid4().hex[:8]}"
        
#         # Génération de l’URL du QR
#         frontend_url = "http://localhost:5173"
#         self.qr_url = f"{frontend_url}/public/qr/{self.id}"

#         # Génération de l’image du QR code
#         qr_img = qrcode.make(self.qr_url)
#         buffer = BytesIO()
#         qr_img.save(buffer, format="PNG")
#         img_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
#         self.qr_image = f"data:image/png;base64,{img_str}"

#         # Sauvegarde finale
#         super().save(*args, **kwargs)

#     @property
#     def is_valid(self):
#         if self.status != 'active':
#             return False
#         if self.expires_at and self.expires_at < timezone.now():
#             return False
#         return True

# class QRPaymentSession(PaymentSession):
#     """Extension de PaymentSession pour les paiements QR"""
#     qr_code = models.ForeignKey(QRCode, on_delete=models.CASCADE, related_name='payment_sessions')
    
#     class Meta:
#         verbose_name = "QR Payment Session"
#         verbose_name_plural = "QR Payment Sessions"
#     def is_expired(self):
  
#       if not self.expires_at:
#         return False
#       return timezone.now() > self.expires_at

# # Dans la classe PaymentSession, assurez-vous que cette méthode existe :
#     def is_expired(self):
#      """Vérifier si la session a expiré"""
#      if not self.expires_at:
#         return False
#      return timezone.now() > self.expires_at

# class QRPaymentOTP(OTPBase):
#     """OTP pour paiements QR"""
#     qr_payment_session = models.ForeignKey(QRPaymentSession, on_delete=models.CASCADE, related_name='qr_otps')
#     phone_number = models.CharField(max_length=20)
#     wallet_provider = models.ForeignKey(WalletProvider, on_delete=models.CASCADE)
    
#     def __str__(self):
#         return f"QR Payment OTP for session {self.qr_payment_session.session_id}"
    
#     class Meta:
#         verbose_name = "QR Payment OTP"
#         verbose_name_plural = "QR Payment OTPs"

# qr_models.py - Refactored QR Code Models
from django.utils import timezone
from django.core.exceptions import ValidationError

def generate_qr_id():
    """Generate unique QR code ID"""
    return f"qr_{uuid.uuid4().hex[:12]}"


class QRCodeBase(models.Model):
    """Abstract base model for QR Codes"""
    
    TYPE_CHOICES = [
        ('static', 'Static Amount'),
        ('dynamic', 'Dynamic Amount'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('expired', 'Expired'),
    ]
    
    id = models.CharField(
        max_length=50,
        primary_key=True,
        default=generate_qr_id,
        editable=False
    )
    merchant = models.ForeignKey(
        'Merchant',
        on_delete=models.CASCADE,
        related_name='qr_codes'
    )
    name = models.CharField(
        max_length=255,
        help_text="Display name for the QR code"
    )
    description = models.TextField(
        blank=True,
        null=True,
        help_text="Optional description"
    )
    qr_type = models.CharField(
        max_length=20,
        choices=TYPE_CHOICES,
        default='static'
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active'
    )
    
    # Statistics
    scans_count = models.PositiveIntegerField(default=0)
    total_revenue = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        default=0
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        abstract = True
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.id})"
    
    @property
    def is_valid(self):
        """Check if QR code is valid and not expired"""
        if self.status != 'active':
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True
    
    @property
    def is_expired(self):
        """Check if QR code is expired"""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    def increment_scans(self):
        """Safely increment scan count"""
        self.scans_count += 1
        self.save(update_fields=['scans_count'])

class QRCode(QRCodeBase):
    fixed_amount = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Fixed amount for static QR codes"
    )

    class Meta:
        verbose_name = "QR Code"
        verbose_name_plural = "QR Codes"
        indexes = [
            models.Index(fields=['status'], name='qr_status_idx'),  # only valid fields
            models.Index(fields=['created_at'], name='qr_created_at_idx'),
        ]

class QRPaymentSession(models.Model):
    """QR Code Payment Session"""
    
    STATUS_CHOICES = [
        ('initiated', 'Initiated'),
        ('otp_sent', 'OTP Sent'),
        ('otp_verified', 'OTP Verified'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('expired', 'Expired'),
    ]
    
    session_id = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False
    )
    qr_code = models.ForeignKey(
        QRCode,
        on_delete=models.CASCADE,
        related_name='payment_sessions'
    )
    merchant = models.ForeignKey(
        'Merchant',
        on_delete=models.CASCADE,
        related_name='qr_payment_sessions'
        
    )
    
    # Payment details
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='MRU')
    
    # Customer info
    customer_phone = models.CharField(max_length=20)
    customer_wallet_type = models.CharField(
        max_length=50,
        null=True,
        blank=True
    )
    
    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='initiated'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = "QR Payment Session"
        verbose_name_plural = "QR Payment Sessions"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"QR Payment {self.session_id}"
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(minutes=15)
        super().save(*args, **kwargs)
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    @property
    def can_process(self):
        """Check if session can be processed"""
        return self.status in ['initiated', 'otp_sent', 'otp_verified']


class QRPaymentOTP(models.Model):
    """OTP for QR Code Payments"""
    
    OTP_EXPIRY_SECONDS = 300  # 5 minutes
    
    payment_session = models.ForeignKey(
        QRPaymentSession,
        on_delete=models.CASCADE,
        related_name='otps'
    )
    code = models.CharField(max_length=6)
    phone_number = models.CharField(max_length=20)
    
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = "QR Payment OTP"
        verbose_name_plural = "QR Payment OTPs"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"OTP for {self.payment_session.session_id}"
    
    @property
    def is_expired(self):
        now = timezone.now()
        expiry = self.created_at + timezone.timedelta(seconds=self.OTP_EXPIRY_SECONDS)
        return now > expiry
    
    @property
    def time_remaining(self):
        """Get seconds remaining until OTP expires"""
        if self.is_expired:
            return 0
        expiry = self.created_at + timezone.timedelta(seconds=self.OTP_EXPIRY_SECONDS)
        remaining = (expiry - timezone.now()).total_seconds()
        return max(0, int(remaining))
    
    def verify(self, provided_code):
        """Verify OTP code"""
        if self.is_used:
            raise ValidationError("OTP has already been used")
        if self.is_expired:
            raise ValidationError("OTP has expired")
        if self.code != provided_code:
            raise ValidationError("Invalid OTP code")
        
        self.is_used = True
        self.verified_at = timezone.now()
        self.save()
        return True
