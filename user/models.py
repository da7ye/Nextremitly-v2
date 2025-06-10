from django.db import models
from django.contrib.auth.base_user import  BaseUserManager
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone



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


# Add this to your models.py file

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

