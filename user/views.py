# views.py
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.generics import RetrieveUpdateAPIView
from django.contrib.auth import login, logout
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from .models import CustUser, Buyer, Merchant, OTP_User
from .serializers import (
    BuyerRegistrationSerializer, MerchantRegistrationSerializer,
    LoginSerializer, UserProfileSerializer, BuyerProfileSerializer,
    MerchantProfileSerializer, PasswordChangeSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    EmailVerificationSerializer, ResendOTPSerializer
)
import random
import string


def generate_otp():
    """Generate a 6-digit OTP code"""
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(email, otp_code, purpose='verification'):
    """Send OTP via email"""
    subject_map = {
        'verification': 'Account Verification Code',
        'password_reset': 'Password Reset Code',
    }
    
    subject = subject_map.get(purpose, 'Verification Code')
    message = f'Your {purpose} code is: {otp_code}. This code will expire in 5 minutes.'
    
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False
        )
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


class BuyerRegistrationView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = BuyerRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            buyer = serializer.save()
            
            # Generate and send OTP
            otp_code = generate_otp()
            OTP_User.objects.create(
                user=buyer,
                code=otp_code,
                purpose='verification'
            )
            
            # Send verification email
            email_sent = send_otp_email(buyer.email, otp_code, 'verification')
            
            # Create token
            token, created = Token.objects.get_or_create(user=buyer)
            
            return Response({
                'message': 'Buyer account created successfully',
                'user_id': buyer.id,
                'email': buyer.email,
                'token': token.key,
                'email_sent': email_sent,
                'verification_required': True
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MerchantRegistrationView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = MerchantRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            merchant = serializer.save()
            
            # Generate and send OTP
            otp_code = generate_otp()
            OTP_User.objects.create(
                user=merchant,
                code=otp_code,
                purpose='verification'
            )
            
            # Send verification email
            email_sent = send_otp_email(merchant.email, otp_code, 'verification')
            
            # Create token
            token, created = Token.objects.get_or_create(user=merchant)
            
            return Response({
                'message': 'Merchant account created successfully',
                'user_id': merchant.id,
                'email': merchant.email,
                'token': token.key,
                'email_sent': email_sent,
                'verification_required': True,
                'note': 'Account requires admin verification before activation'
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Create or get token
            token, created = Token.objects.get_or_create(user=user)
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            return Response({
                'message': 'Login successful',
                'token': token.key,
                'user_type': user.user_type,
                'user_id': user.id,
                'email': user.email,
                'is_verified': user.is_verified
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            # Delete the token
            request.user.auth_token.delete()
            return Response({
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': 'Something went wrong'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserProfileView(RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        user = self.request.user
        if user.user_type == 'buyer':
            return BuyerProfileSerializer
        elif user.user_type == 'merchant':
            return MerchantProfileSerializer
        return UserProfileSerializer
    
    def get_object(self):
        user = self.request.user
        if user.user_type == 'buyer':
            return Buyer.objects.get(id=user.id)
        elif user.user_type == 'merchant':
            return Merchant.objects.get(id=user.id)
        return user


class PasswordChangeView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            
            # Delete all tokens to force re-login
            user.auth_token.delete()
            
            return Response({
                'message': 'Password changed successfully. Please login again.'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = CustUser.objects.get(email=email)
            
            # Generate and send OTP
            otp_code = generate_otp()
            
            # Delete existing password reset OTPs
            OTP_User.objects.filter(user=user, purpose='password_reset').delete()
            
            # Create new OTP
            OTP_User.objects.create(
                user=user,
                code=otp_code,
                purpose='password_reset'
            )
            
            # Send reset email
            email_sent = send_otp_email(email, otp_code, 'password_reset')
            
            return Response({
                'message': 'Password reset code sent to your email',
                'email_sent': email_sent
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            new_password = serializer.validated_data['new_password']
            
            try:
                user = CustUser.objects.get(email=email)
                otp = OTP_User.objects.get(
                    user=user,
                    code=otp_code,
                    purpose='password_reset',
                    is_used=False
                )
                
                if otp.is_expired():
                    return Response({
                        'error': 'OTP has expired. Please request a new one.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Reset password
                user.set_password(new_password)
                user.save()
                
                # Mark OTP as used
                otp.is_used = True
                otp.save()
                
                # Delete all user tokens to force re-login
                Token.objects.filter(user=user).delete()
                
                return Response({
                    'message': 'Password reset successful. Please login with your new password.'
                }, status=status.HTTP_200_OK)
                
            except (CustUser.DoesNotExist, OTP_User.DoesNotExist):
                return Response({
                    'error': 'Invalid email or OTP code'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp_code']
            
            try:
                user = CustUser.objects.get(email=email)
                otp = OTP_User.objects.get(
                    user=user,
                    code=otp_code,
                    purpose='verification',
                    is_used=False
                )
                
                if otp.is_expired():
                    return Response({
                        'error': 'OTP has expired. Please request a new one.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Verify user
                user.is_verified = True
                user.date_verified = timezone.now()
                user.save()
                
                # Mark OTP as used
                otp.is_used = True
                otp.save()
                
                return Response({
                    'message': 'Email verified successfully',
                    'is_verified': True
                }, status=status.HTTP_200_OK)
                
            except (CustUser.DoesNotExist, OTP_User.DoesNotExist):
                return Response({
                    'error': 'Invalid email or OTP code'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendOTPView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            purpose = serializer.validated_data['purpose']
            
            try:
                user = CustUser.objects.get(email=email)
                
                # Delete existing OTPs for this purpose
                OTP_User.objects.filter(user=user, purpose=purpose).delete()
                
                # Generate new OTP
                otp_code = generate_otp()
                OTP_User.objects.create(
                    user=user,
                    code=otp_code,
                    purpose=purpose
                )
                
                # Send email
                email_sent = send_otp_email(email, otp_code, purpose)
                
                return Response({
                    'message': f'New {purpose} code sent to your email',
                    'email_sent': email_sent
                }, status=status.HTTP_200_OK)
                
            except CustUser.DoesNotExist:
                return Response({
                    'error': 'User with this email does not exist'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_status(request):
    """Get current user status"""
    user = request.user
    return Response({
        'user_id': user.id,
        'email': user.email,
        'user_type': user.user_type,
        'is_verified': user.is_verified,
        'is_active': user.is_active,
        'date_joined': user.date_joined
    })