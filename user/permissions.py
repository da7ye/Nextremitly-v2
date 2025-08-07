# permissions.py
from rest_framework import permissions


class IsBuyer(permissions.BasePermission):
    """
    Custom permission to only allow buyers to access buyer-specific views.
    """
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.user_type == 'buyer'
        )
# Dans votre modèle QRCode
class Meta:
    permissions = [
        ('delete_qrcode', 'Peut supprimer un QR code'),
    ]

class IsMerchant(permissions.BasePermission):
    """
    Custom permission to only allow merchants to access merchant-specific views.
    """
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.user_type == 'merchant'
        )


class IsVerifiedUser(permissions.BasePermission):
    """
    Custom permission to only allow verified users.
    """
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.is_verified
        )


class IsActiveMerchant(permissions.BasePermission):
    """
    Custom permission to only allow active and verified merchants.
    """
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.user_type == 'merchant' and
            hasattr(request.user, 'merchant') and
            request.user.merchant.activation_status and
            request.user.merchant.verification_status
        )


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the object.
        return obj.user == request.user or obj == request.user


# mixins.py
from django.http import JsonResponse
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status


class UserTypeMixin:
    """
    Mixin to add user type checking functionality to views.
    """
    
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            # Add user type to request for easy access
            request.user_type = request.user.user_type
        return super().dispatch(request, *args, **kwargs)


class VerificationRequiredMixin:
    """
    Mixin to require email verification for certain actions.
    """
    
    def check_verification_required(self, request):
        if not request.user.is_verified:
            return Response({
                'error': 'Email verification required',
                'verification_required': True
            }, status=status.HTTP_403_FORBIDDEN)
        return None


class OTPValidationMixin:
    """
    Mixin to handle OTP validation.
    """
    
    def validate_otp(self, user, otp_code, purpose='verification'):
        from .models import OTP_User
        
        try:
            otp = OTP_User.objects.get(
                user=user,
                code=otp_code,
                purpose=purpose,
                is_used=False
            )
            
            if otp.is_expired():
                return False, 'OTP has expired'
            
            # Mark as used
            otp.is_used = True
            otp.save()
            
            return True, 'OTP validated successfully'
            
        except OTP_User.DoesNotExist:
            return False, 'Invalid OTP code'


# decorators.py
from functools import wraps
from django.http import JsonResponse
from rest_framework import status


def buyer_required(view_func):
    """
    Decorator for views that require buyer user type.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if request.user.user_type != 'buyer':
            return JsonResponse({
                'error': 'Buyer access required'
            }, status=status.HTTP_403_FORBIDDEN)
        
        return view_func(request, *args, **kwargs)
    return wrapper


def merchant_required(view_func):
    """
    Decorator for views that require merchant user type.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if request.user.user_type != 'merchant':
            return JsonResponse({
                'error': 'Merchant access required'
            }, status=status.HTTP_403_FORBIDDEN)
        
        return view_func(request, *args, **kwargs)
    return wrapper


def verification_required(view_func):
    """
    Decorator for views that require email verification.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if not request.user.is_verified:
            return JsonResponse({
                'error': 'Email verification required',
                'verification_required': True
            }, status=status.HTTP_403_FORBIDDEN)
        
        return view_func(request, *args, **kwargs)
    return wrapper


def active_merchant_required(view_func):
    """
    Decorator for views that require active and verified merchant.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': 'Authentication required'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        if request.user.user_type != 'merchant':
            return JsonResponse({
                'error': 'Merchant access required'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            merchant = request.user.merchant
            if not merchant.activation_status:
                return JsonResponse({
                    'error': 'Merchant account is not activated'
                }, status=status.HTTP_403_FORBIDDEN)
            
            if not merchant.verification_status:
                return JsonResponse({
                    'error': 'Merchant account is not verified'
                }, status=status.HTTP_403_FORBIDDEN)
        
        except AttributeError:
            return JsonResponse({
                'error': 'Invalid merchant account'
            }, status=status.HTTP_403_FORBIDDEN)
        
        return view_func(request, *args, **kwargs)
    return wrapper