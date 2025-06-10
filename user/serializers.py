# serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import CustUser, Buyer, Merchant
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