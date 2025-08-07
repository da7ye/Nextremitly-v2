# views.py
from jsonschema import ValidationError
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
from django.db.models import Sum, Count
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny,IsAuthenticated
from django.shortcuts import get_object_or_404
import random
import string
from rest_framework import generics

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




from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView, ListAPIView
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Sum, Count, Q
from django.db import transaction
from django.core.mail import send_mail
from django.conf import settings
import requests
import random
import string
from datetime import timedelta, date

from .models import (
    WalletProvider, MerchantWallet, PaymentSession, Transaction, 
    PaymentOTP, APIKey, Merchant, Buyer
)
from .serializers import (
    WalletProviderSerializer, MerchantWalletSerializer, PaymentSessionCreateSerializer,
    PaymentSessionSerializer, PaymentSessionUpdateSerializer, TransactionSerializer,
    PaymentInitiateSerializer, PaymentConfirmSerializer, APIKeySerializer,
    MerchantDashboardSerializer, BuyerDashboardSerializer
)
from .permissions import IsMerchant, IsBuyer, IsActiveMerchant
from django.db import transaction
from django.shortcuts import get_object_or_404
import random
import requests
from django.utils import timezone


# ============================================================================
# WALLET MANAGEMENT VIEWS
# ============================================================================

class WalletProviderListView(ListAPIView):
    """List all available wallet providers"""
    queryset = WalletProvider.objects.filter(is_active=True)
    serializer_class = WalletProviderSerializer
    permission_classes = [permissions.IsAuthenticated]



class MerchantWalletListCreateView(ListCreateAPIView):
    """List and create merchant wallets"""
    serializer_class = MerchantWalletSerializer
    permission_classes = [IsMerchant]
    
    def get_queryset(self):
        # Get the Merchant instance, not CustUser
        try:
            merchant = Merchant.objects.get(id=self.request.user.id)
            return MerchantWallet.objects.filter(merchant=merchant).select_related('provider')
        except Merchant.DoesNotExist:
            return MerchantWallet.objects.none()
    
    def perform_create(self, serializer):
        # Get the Merchant instance, not CustUser
        try:
            merchant = Merchant.objects.get(id=self.request.user.id)
            serializer.save(merchant=merchant)
        except Merchant.DoesNotExist:
            raise ValidationError("Merchant account not found")


class MerchantWalletDetailView(RetrieveUpdateDestroyAPIView):
    """Retrieve, update, delete merchant wallet"""
    serializer_class = MerchantWalletSerializer
    permission_classes = [IsMerchant]
    
    def get_queryset(self):
        return MerchantWallet.objects.filter(merchant=self.request.user)


# ============================================================================
# PAYMENT SESSION MANAGEMENT (FOR ECOMMERCE INTEGRATION)
# ============================================================================



class PaymentSessionCreateAPIView(APIView):
    """Create payment session - used by ecommerce platforms"""
    permission_classes = [permissions.AllowAny]  # API key authentication handled separately
    
    def post(self, request):
        # Validate API key
        api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not api_key:
            return Response({'error': 'API key required'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Find merchant by API key
        merchant = self.get_merchant_from_api_key(api_key)
        if not merchant:
            return Response({'error': 'Invalid API key'}, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = PaymentSessionCreateSerializer(data=request.data)
        if serializer.is_valid():
            payment_session = serializer.save(merchant=merchant)
            
            response_data = {
                'session_id': payment_session.session_id,
                'payment_url': f"{settings.FRONTEND_URL}/payment/{payment_session.session_id}",
                'status': payment_session.status,
                'expires_at': payment_session.expires_at,
                'amount': payment_session.amount,
                'currency': payment_session.currency
            }
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_merchant_from_api_key(self, api_key):
        """Validate API key and return merchant"""
        try:
            print(f"Validating API key: {api_key}")  # Debug print
            
            # Extract key type and validate format
            if not api_key.startswith(('nxt_test_', 'nxt_live_')):
                print("Invalid key format")  # Debug print
                return None
            
            key_parts = api_key.split('_')
            if len(key_parts) != 3:
                print("Invalid key parts")  # Debug print
                return None
            
            is_test = key_parts[1] == 'test'
            print(f"Is test mode: {is_test}")  # Debug print
            
            # Find matching API key
            api_keys = APIKey.objects.filter(is_active=True, is_test_mode=is_test)
            print(f"Found {api_keys.count()} active API keys")  # Debug print
            
            for api_key_obj in api_keys:
                print(f"Checking against key with prefix: {api_key_obj.key_prefix}")  # Debug print
                if api_key_obj.check_key(api_key):
                    print("Key match found!")  # Debug print
                    # Update last used
                    api_key_obj.last_used_at = timezone.now()
                    api_key_obj.save(update_fields=['last_used_at'])
                    
                    # Return the Merchant instance
                    try:
                        return Merchant.objects.get(id=api_key_obj.merchant.id)
                    except Merchant.DoesNotExist:
                        print("Merchant not found")  # Debug print
                        return None
            
            print("No matching key found")  # Debug print
            return None
        except Exception as e:
            print(f"Exception in key validation: {e}")  # Debug print
            return None


class PaymentSessionDetailAPIView(APIView):
    """Get payment session details - used by payment widget"""
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, session_id):
        try:
            payment_session = PaymentSession.objects.get(session_id=session_id)
            
            if payment_session.is_expired():
                payment_session.status = 'expired'
                payment_session.save()
                return Response({'error': 'Payment session expired'}, status=status.HTTP_410_GONE)
            
            serializer = PaymentSessionSerializer(payment_session)
            return Response(serializer.data)
        
        except PaymentSession.DoesNotExist:
            return Response({'error': 'Payment session not found'}, status=status.HTTP_404_NOT_FOUND)


# ============================================================================
# PAYMENT FLOW VIEWS (FOR PAYMENT WIDGET)
# ============================================================================

class PaymentAuthenticateView(APIView):
    """Authenticate user for payment session"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, session_id):
        try:
            payment_session = get_object_or_404(PaymentSession, session_id=session_id)
            
            if payment_session.is_expired():
                return Response({'error': 'Payment session expired'}, status=status.HTTP_410_GONE)
            
            if payment_session.status != 'pending':
                return Response({'error': 'Invalid session status'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Update session with authenticated user
            payment_session.authenticated_user = request.user
            payment_session.status = 'authenticated'
            payment_session.save()
            
            # Get merchant's available wallets
            wallets = MerchantWallet.objects.filter(
                merchant=payment_session.merchant,
                is_active=True
            ).select_related('provider')
            
            wallet_data = MerchantWalletSerializer(wallets, many=True).data
            
            return Response({
                'status': 'authenticated',
                'available_wallets': wallet_data,
                'user': {
                    'name': request.user.nom_complet,
                    'email': request.user.email
                }
            })
        
        except PaymentSession.DoesNotExist:
            return Response({'error': 'Payment session not found'}, status=status.HTTP_404_NOT_FOUND)


class PaymentSelectWalletView(APIView):
    """Select wallet for payment"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, session_id):
        wallet_id = request.data.get('wallet_id')
        
        try:
            payment_session = get_object_or_404(PaymentSession, session_id=session_id)
            
            if payment_session.authenticated_user != request.user:
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
            
            if payment_session.status != 'authenticated':
                return Response({'error': 'Invalid session status'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate wallet belongs to merchant
            wallet = get_object_or_404(
                MerchantWallet, 
                id=wallet_id, 
                merchant=payment_session.merchant,
                is_active=True
            )
            
            payment_session.selected_wallet = wallet
            payment_session.status = 'wallet_selected'
            payment_session.save()
            
            return Response({
                'status': 'wallet_selected',
                'selected_wallet': MerchantWalletSerializer(wallet).data
            })
        
        except PaymentSession.DoesNotExist:
            return Response({'error': 'Payment session not found'}, status=status.HTTP_404_NOT_FOUND)
        except MerchantWallet.DoesNotExist:
            return Response({'error': 'Invalid wallet selected'}, status=status.HTTP_400_BAD_REQUEST)


class PaymentInitiateView(APIView):
    """Initiate payment by entering customer phone number"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, session_id):
        serializer = PaymentInitiateSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            payment_session = get_object_or_404(PaymentSession, session_id=session_id)
            
            if payment_session.authenticated_user != request.user:
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
            
            if payment_session.status != 'wallet_selected':
                return Response({'error': 'Invalid session status'}, status=status.HTTP_400_BAD_REQUEST)
            
            phone_number = serializer.validated_data['phone_number']
            
            # Generate and send OTP
            otp_code = self.generate_otp()
            
            # Delete existing OTPs for this session
            PaymentOTP.objects.filter(payment_session=payment_session).delete()
            
            # Create new OTP
            PaymentOTP.objects.create(
                payment_session=payment_session,
                phone_number=phone_number,
                code=otp_code,
                purpose='transaction'
            )
            
            # Update payment session
            payment_session.customer_wallet_phone = phone_number
            payment_session.status = 'otp_sent'
            payment_session.save()
            
            # Send OTP (simulated)
            self.send_payment_otp(phone_number, otp_code, payment_session.amount)
            
            return Response({
                'status': 'otp_sent',
                'message': 'OTP sent to your phone number',
                'phone_number': phone_number[-4:].rjust(len(phone_number), '*')  # Masked phone
            })
        
        except PaymentSession.DoesNotExist:
            return Response({'error': 'Payment session not found'}, status=status.HTTP_404_NOT_FOUND)
    
    def generate_otp(self):
        return ''.join(random.choices(string.digits, k=6))
    
    def send_payment_otp(self, phone_number, otp_code, amount):
        """Send OTP via SMS (simulated)"""
        # In production, integrate with SMS provider
        print(f"SMS to {phone_number}: Your Nextremitly payment OTP is {otp_code} for amount {amount} MRU")
        return True


class PaymentConfirmView(APIView):
    """Confirm payment with OTP"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, session_id):
        serializer = PaymentConfirmSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            payment_session = get_object_or_404(PaymentSession, session_id=session_id)
            
            if payment_session.authenticated_user != request.user:
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
            
            if payment_session.status != 'otp_sent':
                return Response({'error': 'Invalid session status'}, status=status.HTTP_400_BAD_REQUEST)
            
            otp_code = serializer.validated_data['otp_code']
            phone_number = serializer.validated_data['phone_number']
            
            # Verify OTP
            try:
                otp = PaymentOTP.objects.get(
                    payment_session=payment_session,
                    phone_number=phone_number,
                    code=otp_code,
                    is_used=False
                )
                
                if otp.is_expired():
                    return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)
                
                # Mark OTP as used
                otp.is_used = True
                otp.save()
                
                # Process payment
                return self.process_payment(payment_session)
                
            except PaymentOTP.DoesNotExist:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        
        except PaymentSession.DoesNotExist:
            return Response({'error': 'Payment session not found'}, status=status.HTTP_404_NOT_FOUND)
    
    def process_payment(self, payment_session):
        """Process the actual payment"""
        try:
            # Update session status
            payment_session.status = 'processing'
            payment_session.save()
            
            # Calculate fees (2% fee) - Fix: Use Decimal for calculations
            from decimal import Decimal
            fee_amount = payment_session.amount * Decimal('0.02')
            net_amount = payment_session.amount - fee_amount
            
            # Get the Merchant instance - FIX: Ensure we have the correct merchant
            try:
                merchant_instance = Merchant.objects.get(id=payment_session.merchant.id)
            except Merchant.DoesNotExist:
                payment_session.status = 'failed'
                payment_session.save()
                return Response({
                    'status': 'failed',
                    'error': 'Merchant not found',
                    'redirect_url': payment_session.cancel_url
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create transaction record with proper atomic block handling
            with transaction.atomic():
                transaction_obj = Transaction.objects.create(
                    payment_session=payment_session,
                    transaction_type='payment',
                    sender=payment_session.authenticated_user,
                    receiver=merchant_instance,  # Use the Merchant instance
                    merchant=merchant_instance,  # Use the Merchant instance
                    amount=payment_session.amount,
                    currency=payment_session.currency,
                    fee_amount=fee_amount,
                    net_amount=net_amount,
                    sender_wallet_provider=payment_session.selected_wallet.provider,
                    sender_wallet_phone=payment_session.customer_wallet_phone,
                    receiver_wallet=payment_session.selected_wallet,
                    status='processing',
                    description=payment_session.description or 'Payment via Nextremitly'
                )
            
            # Simulate bank API call
            bank_response = self.call_bank_api(payment_session, transaction_obj)
            
            if bank_response['success']:
                # Payment successful
                with transaction.atomic():
                    transaction_obj.status = 'completed'
                    transaction_obj.external_transaction_id = bank_response['transaction_id']
                    transaction_obj.provider_response = bank_response
                    transaction_obj.completed_at = timezone.now()
                    transaction_obj.save()
                    
                    payment_session.status = 'completed'
                    payment_session.completed_at = timezone.now()
                    payment_session.save()
                
                # Send webhook to ecommerce (async)
                try:
                    self.send_webhook(payment_session, transaction_obj)
                except Exception as e:
                    # Log webhook error but don't fail the payment
                    print(f"Webhook error: {e}")
                
                return Response({
                    'status': 'completed',
                    'transaction_id': transaction_obj.transaction_id,
                    'amount': payment_session.amount,
                    'currency': payment_session.currency,
                    'redirect_url': payment_session.success_url
                })
            else:
                # Payment failed
                with transaction.atomic():
                    transaction_obj.status = 'failed'
                    transaction_obj.failure_reason = bank_response.get('error', 'Payment failed')
                    transaction_obj.provider_response = bank_response
                    transaction_obj.save()
                    
                    payment_session.status = 'failed'
                    payment_session.save()
                
                return Response({
                    'status': 'failed',
                    'error': bank_response.get('error', 'Payment failed'),
                    'redirect_url': payment_session.cancel_url
                }, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            # Handle unexpected errors
            print(f"Payment processing error: {e}")  # Add logging
            try:
                payment_session.status = 'failed'
                payment_session.save()
            except Exception:
                pass  # Ignore save errors in exception handler
            
            return Response({
                'status': 'failed',
                'error': 'Payment processing failed',
                'redirect_url': payment_session.cancel_url
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def call_bank_api(self, payment_session, transaction):
        """Simulate bank API call"""
        # In production, this would call the actual bank API
        import time
        time.sleep(1)  # Simulate API delay
        
        # Simulate 95% success rate
        success = random.random() < 0.95
        
        if success:
            return {
                'success': True,
                'transaction_id': f"BNK_{random.randint(100000, 999999)}",
                'status': 'completed',
                'amount': float(payment_session.amount),
                'currency': payment_session.currency,
                'timestamp': timezone.now().isoformat()
            }
        else:
            return {
                'success': False,
                'error': 'Insufficient funds',
                'error_code': 'INSUFFICIENT_FUNDS'
            }
    
    def send_webhook(self, payment_session, transaction):
        """Send webhook notification to ecommerce"""
        if not payment_session.webhook_url:
            return
        
        from .models import WebhookLog
        
        payload = {
            'session_id': str(payment_session.session_id),
            'status': payment_session.status,
            'amount': float(payment_session.amount),
            'currency': payment_session.currency,
            'transaction_id': str(transaction.transaction_id),
            'external_transaction_id': transaction.external_transaction_id,
            'completed_at': payment_session.completed_at.isoformat() if payment_session.completed_at else None,
            'metadata': payment_session.metadata
        }
        
        try:
            response = requests.post(
                payment_session.webhook_url,
                json=payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            WebhookLog.objects.create(
                payment_session=payment_session,
                webhook_url=payment_session.webhook_url,
                payload=payload,
                response_status=response.status_code,
                response_body=response.text,
                success=response.status_code == 200
            )
        
        except Exception as e:
            WebhookLog.objects.create(
                payment_session=payment_session,
                webhook_url=payment_session.webhook_url,
                payload=payload,
                success=False
            )
            raise e  # Re-raise for logging


# ============================================================================
# DASHBOARD VIEWS
# ============================================================================

class MerchantDashboardView(APIView):
    """Merchant dashboard with analytics"""
    permission_classes = [IsMerchant]
    
    def get(self, request):
        merchant = request.user
        today = timezone.now().date()
        
        # Calculate metrics
        total_revenue = Transaction.objects.filter(
            merchant=merchant,
            status='completed'
        ).aggregate(total=Sum('net_amount'))['total'] or 0
        
        daily_revenue = Transaction.objects.filter(
            merchant=merchant,
            status='completed',
            created_at__date=today
        ).aggregate(total=Sum('net_amount'))['total'] or 0
        
        pending_amount = Transaction.objects.filter(
            merchant=merchant,
            status__in=['pending', 'processing']
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        active_wallets_count = MerchantWallet.objects.filter(
            merchant=merchant,
            is_active=True
        ).count()
        
        transaction_stats = Transaction.objects.filter(merchant=merchant).aggregate(
            total=Count('id'),
            successful=Count('id', filter=Q(status='completed'))
        )
        
        # Recent transactions
        recent_transactions = Transaction.objects.filter(
            merchant=merchant
        ).select_related('sender', 'sender_wallet_provider', 'receiver_wallet')[:10]
        
        data = {
            'total_revenue': total_revenue,
            'daily_revenue': daily_revenue,
            'pending_amount': pending_amount,
            'active_wallets_count': active_wallets_count,
            'total_transactions': transaction_stats['total'],
            'successful_transactions': transaction_stats['successful'],
            'recent_transactions': TransactionSerializer(recent_transactions, many=True).data
        }
        
        return Response(data)


class BuyerDashboardView(APIView):
    """Buyer dashboard with transaction history"""
    permission_classes = [IsBuyer]
    
    def get(self, request):
        buyer = request.user
        
        # Calculate metrics
        sent_transactions = Transaction.objects.filter(
            sender=buyer,
            status='completed'
        )
        
        received_transactions = Transaction.objects.filter(
            receiver=buyer,
            status='completed'
        )
        
        total_spent = sent_transactions.aggregate(total=Sum('amount'))['total'] or 0
        total_received = received_transactions.aggregate(total=Sum('amount'))['total'] or 0
        
        pending_count = Transaction.objects.filter(
            Q(sender=buyer) | Q(receiver=buyer),
            status__in=['pending', 'processing']
        ).count()
        
        completed_count = Transaction.objects.filter(
            Q(sender=buyer) | Q(receiver=buyer),
            status='completed'
        ).count()
        
        # Recent transactions
        recent_transactions = Transaction.objects.filter(
            Q(sender=buyer) | Q(receiver=buyer)
        ).select_related('merchant', 'sender_wallet_provider', 'receiver_wallet')[:10]
        
        data = {
            'total_spent': total_spent,
            'total_received': total_received,
            'pending_transactions': pending_count,
            'completed_transactions': completed_count,
            'recent_transactions': TransactionSerializer(recent_transactions, many=True).data
        }
        
        return Response(data)


# ============================================================================
# TRANSACTION VIEWS
# ============================================================================

class TransactionListView(ListAPIView):
    """List transactions for authenticated user"""
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        
        if user.user_type == 'merchant':
            return Transaction.objects.filter(merchant=user).select_related(
                'sender', 'receiver', 'sender_wallet_provider', 'receiver_wallet'
            )
        else:
            return Transaction.objects.filter(
                Q(sender=user) | Q(receiver=user)
            ).select_related(
                'merchant', 'sender_wallet_provider', 'receiver_wallet'
            )


class TransactionDetailView(APIView):
    """Get transaction details"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, transaction_id):
        try:
            user = request.user
            
            if user.user_type == 'merchant':
                transaction_obj = Transaction.objects.get(
                    transaction_id=transaction_id,
                    merchant=user
                )
            else:
                transaction_obj = Transaction.objects.get(
                    transaction_id=transaction_id
                ).filter(Q(sender=user) | Q(receiver=user))
            
            serializer = TransactionSerializer(transaction_obj)
            return Response(serializer.data)
        
        except Transaction.DoesNotExist:
            return Response({'error': 'Transaction not found'}, status=status.HTTP_404_NOT_FOUND)




class APIKeyListCreateView(ListCreateAPIView):
    """List and create API keys for merchants"""
    serializer_class = APIKeySerializer
    permission_classes = [IsMerchant]
    
    def get_queryset(self):
        try:
            merchant = Merchant.objects.get(id=self.request.user.id)
            return APIKey.objects.filter(merchant=merchant)
        except Merchant.DoesNotExist:
            return APIKey.objects.none()
    
    def list(self, request, *args, **kwargs):
        """Override list to handle the key field properly"""
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        # For the list view, we don't return the actual key for security
        # The frontend should store the key when it's first created
        return Response(serializer.data)
    
    def perform_create(self, serializer):
        try:
            merchant = Merchant.objects.get(id=self.request.user.id)
            api_key_obj = serializer.save(merchant=merchant)
            
            # Generate the actual key and store it
            generated_key = api_key_obj.generate_key()
            
            # Debug: Print the generated key
            print(f"Generated API key: {generated_key}")
            print(f"Key prefix: {api_key_obj.key_prefix}")
            
            # Make sure to return the key in the response
            serializer.instance.key = generated_key
            
        except Merchant.DoesNotExist:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Merchant account not found")

class APIKeyDetailView(RetrieveUpdateDestroyAPIView):
    """Manage individual API keys"""
    serializer_class = APIKeySerializer
    permission_classes = [IsMerchant]
    
    def get_queryset(self):
        try:
            merchant = Merchant.objects.get(id=self.request.user.id)
            return APIKey.objects.filter(merchant=merchant)
        except Merchant.DoesNotExist:
            return APIKey.objects.none()


# ============================================================================
# UTILITY VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def payment_status_webhook(request, session_id):
    """Endpoint for receiving payment status updates from banks"""
    try:
        payment_session = PaymentSession.objects.get(session_id=session_id)
        
        # Verify webhook signature (in production)
        # signature = request.headers.get('X-Webhook-Signature')
        # if not verify_signature(request.body, signature):
        #     return Response({'error': 'Invalid signature'}, status=status.HTTP_401_UNAUTHORIZED)
        
        status_update = request.data.get('status')
        external_tx_id = request.data.get('transaction_id')
        
        if status_update in ['completed', 'failed']:
            transaction_obj = Transaction.objects.filter(
                payment_session=payment_session
            ).first()
            
            if transaction_obj:
                transaction_obj.status = status_update
                transaction_obj.external_transaction_id = external_tx_id
                transaction_obj.provider_response = request.data
                
                if status_update == 'completed':
                    transaction_obj.completed_at = timezone.now()
                    payment_session.status = 'completed'
                    payment_session.completed_at = timezone.now()
                else:
                    payment_session.status = 'failed'
                
                transaction_obj.save()
                payment_session.save()
        
        return Response({'status': 'received'})
    
    except PaymentSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def payment_widget_config(request, session_id):
    """Get configuration for payment widget"""
    try:
        payment_session = PaymentSession.objects.get(session_id=session_id)
        
        if payment_session.is_expired():
            return Response({'error': 'Session expired'}, status=status.HTTP_410_GONE)
        
        config = {
            'session_id': payment_session.session_id,
            'merchant_name': payment_session.merchant.business_name,
            'amount': payment_session.amount,
            'currency': payment_session.currency,
            'description': payment_session.description,
            'widget_url': f"{settings.FRONTEND_URL}/widget/{session_id}",
            'api_base_url': f"{settings.API_BASE_URL}/api/payment"
        }
        
        return Response(config)
    
    except PaymentSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)
    

from .models import WalletVerificationOTP
from .serializers import WalletVerificationRequestSerializer, WalletVerificationConfirmSerializer, WalletVerificationOTPSerializer
import uuid
import random

class WalletVerificationInitiateView(APIView):
    """Initiate wallet verification process"""
    permission_classes = [IsMerchant]
    
    def post(self, request):
        serializer = WalletVerificationRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            merchant = Merchant.objects.get(id=request.user.id)
            provider = WalletProvider.objects.get(id=serializer.validated_data['provider_id'])
            wallet_id = serializer.validated_data['wallet_id']
            
            # Check if wallet already exists for this merchant
            existing_wallet = MerchantWallet.objects.filter(
                merchant=merchant,
                provider=provider,
                wallet_id=wallet_id
            ).first()
            
            if existing_wallet:
                return Response({
                    'error': 'This wallet is already registered for your account'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Simulate bank account verification
            bank_verification = self.verify_wallet_with_bank(provider, wallet_id)
            
            if not bank_verification['success']:
                return Response({
                    'error': bank_verification['error']
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate OTP
            otp_code = self.generate_otp()
            
            # Delete any existing pending verification for the same wallet
            WalletVerificationOTP.objects.filter(
                merchant=merchant,
                wallet_provider=provider,
                wallet_id=wallet_id,
                verification_status='pending'
            ).delete()
            
            # Create verification record
            verification = WalletVerificationOTP.objects.create(
                merchant=merchant,
                wallet_provider=provider,
                wallet_id=wallet_id,
                wallet_name=serializer.validated_data['wallet_name'],
                is_active=serializer.validated_data['is_active'],
                is_primary=serializer.validated_data['is_primary'],
                code=otp_code,
                purpose='verification'
            )
            
            # Send OTP via SMS (simulated)
            self.send_wallet_verification_otp(wallet_id, otp_code, provider.display_name)
            
            return Response({
                'verification_id': verification.id,
                'message': f'Verification OTP sent to {wallet_id}',
                'masked_phone': self.mask_phone_number(wallet_id),
                'provider': provider.display_name
            }, status=status.HTTP_200_OK)
            
        except Merchant.DoesNotExist:
            return Response({'error': 'Merchant account not found'}, status=status.HTTP_400_BAD_REQUEST)
        except WalletProvider.DoesNotExist:
            return Response({'error': 'Invalid wallet provider'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Verification initiation failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def verify_wallet_with_bank(self, provider, wallet_id):
        """Simulate bank account verification with realistic delays"""
        import time
        import random
        
        # Simulate realistic API call delays (2-5 seconds)
        delay = random.uniform(2.0, 5.0)
        time.sleep(delay)
        
        # Simulate network fluctuations - occasionally longer delays
        if random.random() < 0.1:  # 10% chance of slower response
            print(f"Simulating slow bank API response for {provider.display_name}...")
            time.sleep(random.uniform(3.0, 8.0))
        
        # Simulate different scenarios based on phone number
        if wallet_id.endswith('0000'):
            return {
                'success': False,
                'error': f'No {provider.display_name} account found for this number',
                'error_code': 'ACCOUNT_NOT_FOUND'
            }
        elif wallet_id.endswith('1111'):
            return {
                'success': False,
                'error': 'Account is suspended or inactive',
                'error_code': 'ACCOUNT_SUSPENDED'
            }
        elif wallet_id.endswith('2222'):
            return {
                'success': False,
                'error': 'Unable to verify account at this time. Please try again later.',
                'error_code': 'SERVICE_UNAVAILABLE'
            }
        else:
            return {
                'success': True,
                'account_name': f'Account Holder {wallet_id[-4:]}',
                'account_status': 'active',
                'account_type': random.choice(['personal', 'business']),
                'verification_level': random.choice(['basic', 'verified', 'premium'])
            }
    
    def generate_otp(self):
        return ''.join(random.choices(string.digits, k=6))
    
    def send_wallet_verification_otp(self, phone_number, otp_code, provider_name):
        """Send OTP via SMS (simulated with realistic delays)"""
        import time
        import random
        
        # Simulate SMS service delays (1-3 seconds)
        delay = random.uniform(1.0, 3.0)
        print(f"Connecting to SMS gateway for {provider_name}...")
        time.sleep(delay)
        
        # Simulate occasional SMS delivery delays
        if random.random() < 0.15:  # 15% chance of slower SMS delivery
            print("SMS gateway experiencing high traffic. Please wait...")
            time.sleep(random.uniform(2.0, 4.0))
        
        print(f"SMS to {phone_number}: Your {provider_name} wallet verification OTP is {otp_code}. Valid for 5 minutes.")
        
        # Simulate delivery confirmation delay
        time.sleep(random.uniform(0.5, 1.5))
        print(f"SMS delivery confirmed for {phone_number}")
        
        return True
    
    def mask_phone_number(self, phone_number):
        """Mask phone number for display"""
        if len(phone_number) > 4:
            return phone_number[-4:].rjust(len(phone_number), '*')
        return phone_number


class WalletVerificationConfirmView(APIView):
    """Confirm wallet verification with OTP"""
    permission_classes = [IsMerchant]
    
    def post(self, request):
        serializer = WalletVerificationConfirmSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            merchant = Merchant.objects.get(id=request.user.id)
            verification_id = serializer.validated_data['verification_id']
            otp_code = serializer.validated_data['otp_code']
            
            # Get verification record
            verification = WalletVerificationOTP.objects.get(
                id=verification_id,
                merchant=merchant,
                verification_status='pending'
            )
            
            # Check if OTP is expired
            if verification.is_expired():
                verification.verification_status = 'failed'
                verification.save()
                return Response({
                    'error': 'OTP has expired. Please request a new verification.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if OTP is correct
            if verification.code != otp_code:
                return Response({
                    'error': 'Invalid OTP code'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if OTP is already used
            if verification.is_used:
                return Response({
                    'error': 'OTP has already been used'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Verify and create wallet
            with transaction.atomic():
                # Simulate final database operations delay
                import time
                time.sleep(random.uniform(0.5, 1.5))
                
                # Mark OTP as used
                verification.is_used = True
                verification.verification_status = 'verified'
                verification.save()
                
                # If this is primary, unset other primary wallets
                if verification.is_primary:
                    MerchantWallet.objects.filter(
                        merchant=merchant,
                        is_primary=True
                    ).update(is_primary=False)
                
                # Simulate wallet creation processing
                print(f"Creating wallet entry for {merchant.business_name}...")
                time.sleep(random.uniform(0.3, 0.8))
                
                # Create the verified wallet
                wallet = MerchantWallet.objects.create(
                    merchant=merchant,
                    provider=verification.wallet_provider,
                    wallet_id=verification.wallet_id,
                    wallet_name=verification.wallet_name,
                    is_active=verification.is_active,
                    is_primary=verification.is_primary
                )
                
                print(f"Wallet successfully created and linked to merchant account")
            
            return Response({
                'message': 'Wallet verified and added successfully!',
                'wallet': MerchantWalletSerializer(wallet).data
            }, status=status.HTTP_201_CREATED)
            
        except Merchant.DoesNotExist:
            return Response({'error': 'Merchant account not found'}, status=status.HTTP_400_BAD_REQUEST)
        except WalletVerificationOTP.DoesNotExist:
            return Response({'error': 'Invalid verification ID or verification not found'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Wallet verification failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WalletVerificationStatusView(APIView):
    """Get pending wallet verifications"""
    permission_classes = [IsMerchant]
    
    def get(self, request):
        try:
            merchant = Merchant.objects.get(id=request.user.id)
            pending_verifications = WalletVerificationOTP.objects.filter(
                merchant=merchant,
                verification_status='pending'
            ).select_related('wallet_provider')
            
            serializer = WalletVerificationOTPSerializer(pending_verifications, many=True)
            return Response(serializer.data)
        except Merchant.DoesNotExist:
            return Response({'error': 'Merchant account not found'}, status=status.HTTP_400_BAD_REQUEST)
        




from .models import QRCode, QRPaymentSession, QRPaymentOTP  # Vos nouveaux modèles
from .serializers import (
    QRCodeSerializer, QRCodeStatsSerializer, QRPaymentInitiateSerializer,
    QRPaymentSessionSerializer, QRPaymentOTPVerifySerializer
)
import random
import string



class QRCodeListCreateView(generics.ListCreateAPIView):
    serializer_class = QRCodeSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        if self.request.user.user_type == 'merchant':
            try:
                merchant = Merchant.objects.get(id=self.request.user.id)
                queryset = QRCode.objects.filter(merchant=merchant)
                print(f"🔍 Backend: Found {queryset.count()} QR codes for merchant {merchant.id}")
                for qr in queryset:
                    print(f"  - {qr.name} ({qr.id})")
                return queryset
            except Merchant.DoesNotExist:
                print("❌ Backend: Merchant not found")
                return QRCode.objects.none()
        print("❌ Backend: User is not merchant")
        return QRCode.objects.none()
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        print(f"🔍 Backend: Serialized data: {serializer.data}")
        print(f"🔍 Backend: Data type: {type(serializer.data)}")
        print(f"🔍 Backend: Data length: {len(serializer.data) if isinstance(serializer.data, list) else 'not a list'}")
        
        return Response(serializer.data)




class QRCodeDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET: Détails d'un QR code
    PUT/PATCH: Modifier un QR code
    DELETE: Supprimer un QR code
    """
    serializer_class = QRCodeSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):
        """Ne retourne que les QR codes du merchant connecté"""
        if self.request.user.user_type != 'merchant':
            return QRCode.objects.none()
        return QRCode.objects.filter(merchant=self.request.user)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            qr_id = instance.id
            merchant_id = request.user.id

            # Journalisation avant suppression
            print(f"🗑️ Tentative suppression QR {qr_id} par merchant {merchant_id}")

            # Suppression effective
            self.perform_destroy(instance)
            
            print(f"✅ QR {qr_id} supprimé avec succès")

            return Response(
                {
                    "success": True,
                    "message": "QR code supprimé avec succès",
                    "deleted_id": qr_id,
                },
                status=status.HTTP_200_OK
            )

        except QRCode.DoesNotExist:
            print(f"❌ QR code introuvable lors de la suppression")
            return Response(
                {"error": "QR code introuvable"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            print(f"❌ Erreur suppression QR code: {str(e)}")
            return Response(
                {"error": "Une erreur est survenue lors de la suppression"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def qr_code_stats(request):
    """
    GET: Statistiques des QR codes du merchant
    """
    if request.user.user_type != 'merchant':
        return Response({'error': 'Accès reservé aux merchants'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        merchant = Merchant.objects.get(id=request.user.id)
        user_qr_codes = QRCode.objects.filter(merchant=merchant)
        
        stats = {
            'total_qrs': user_qr_codes.count(),
            'active_qrs': user_qr_codes.filter(status='active').count(),
            'total_scans': user_qr_codes.aggregate(Sum('scans_count'))['scans_count__sum'] or 0,
            'total_revenue': user_qr_codes.aggregate(Sum('total_revenue'))['total_revenue__sum'] or 0
        }
        
        serializer = QRCodeStatsSerializer(stats)
        return Response(serializer.data)
    except Merchant.DoesNotExist:
        return Response({'error': 'Merchant non trouvé'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([AllowAny])
def public_qr_detail(request, qr_id):
    """
    GET: Récupérer les détails publics d'un QR code (pour scan)
    """
    try:
        print(f"🔍 Recherche QR Code: {qr_id}")
        qr_code = get_object_or_404(QRCode, id=qr_id)
        
        print(f"✅ QR Code trouvé: {qr_code.name} - Type: {qr_code.qr_type}")
        
        if not qr_code.is_valid:
            print(f"⚠️ QR Code invalide: {qr_code.status}")
            return Response({
                'error': 'QR Code invalide ou expiré',
                'is_valid': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Incrémenter le compteur de scans
        qr_code.scans_count += 1
        qr_code.save()
        
        data = {
            'id': qr_code.id,
            'merchant_name': qr_code.merchant.business_name or qr_code.merchant.nom_complet,
            'merchant_id': qr_code.merchant.id,
            'qr_type': qr_code.qr_type,  # ✅ AJOUT
            'fixed_amount': float(qr_code.fixed_amount) if qr_code.fixed_amount else None,  # ✅ AJOUT
            'description': qr_code.description,  # ✅ AJOUT
            'is_valid': True,
            'is_active': qr_code.status == 'active'
        }
        
        print(f"✅ Données retournées: {data}")
        return Response(data)
        
    except QRCode.DoesNotExist:
        print(f"❌ QR Code non trouvé: {qr_id}")
        return Response({
            'error': 'QR Code introuvable',
            'is_valid': False
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print(f"❌ Erreur inattendue: {e}")
        return Response({
            'error': 'Erreur serveur',
            'is_valid': False
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def initiate_qr_payment(request, qr_id):
    """
    POST: Initier un paiement via QR code (statique ou dynamique)
    """
    try:
        qr_code = get_object_or_404(QRCode, id=qr_id)
        
        if not qr_code.is_valid:
            return Response({
                'error': 'QR Code invalide ou expiré'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = QRPaymentInitiateSerializer(data=request.data)
        
        if serializer.is_valid():
            # ✅ LOGIQUE DIFFÉRENTE SELON LE TYPE DE QR
            if qr_code.qr_type == 'static':
                # Pour QR statique : utiliser le montant fixe du QR code
                if qr_code.fixed_amount is None:
                    return Response({
                        'error': 'Ce QR code statique n\'a pas de montant défini'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                amount = qr_code.fixed_amount
                print(f"💰 QR Statique - Montant fixe utilisé: {amount} MRU")
                
            else:
                # Pour QR dynamique : utiliser le montant fourni par le client
                amount = serializer.validated_data.get('amount')
                if not amount:
                    return Response({
                        'error': 'Le montant est requis pour un QR code dynamique'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if amount <= 0:
                    return Response({
                        'error': 'Le montant doit être supérieur à 0'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if amount > 1000000:
                    return Response({
                        'error': 'Le montant ne peut pas dépasser 1 000 000 MRU'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                print(f"💰 QR Dynamique - Montant client: {amount} MRU")
            
            # Récupérer le wallet provider
            try:
                wallet_provider = WalletProvider.objects.get(
                    name=serializer.validated_data['wallet_type'],
                    is_active=True
                )
            except WalletProvider.DoesNotExist:
                return Response({
                    'error': 'Portefeuille non supporté'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Créer une session de paiement QR
            payment_session = QRPaymentSession.objects.create(
                qr_code=qr_code,
                merchant=qr_code.merchant,
                amount=amount,  # ✅ Montant selon le type de QR
                currency='MRU',
                description=f"Paiement QR Code: {qr_code.name} ({'Montant fixe' if qr_code.qr_type == 'static' else 'Montant variable'})",
                customer_phone=serializer.validated_data['phone_number'],
                customer_wallet_phone=serializer.validated_data['phone_number'],
                status='wallet_selected',
                expires_at=timezone.now() + timezone.timedelta(minutes=15)
            )
            
            # Générer un code OTP
            otp_code = ''.join(random.choices(string.digits, k=4))
            
            qr_otp = QRPaymentOTP.objects.create(
                qr_payment_session=payment_session,
                phone_number=serializer.validated_data['phone_number'],
                wallet_provider=wallet_provider,
                code=otp_code,
                purpose='transaction'
            )
            
            # Marquer la session comme OTP envoyé
            payment_session.status = 'otp_sent'
            payment_session.save()
            
            # Simulation d'envoi OTP
            print(f"SMS to {serializer.validated_data['phone_number']}: Your QR payment OTP is {otp_code}")
            print(f"QR Type: {qr_code.qr_type} | Amount: {amount} MRU")
            
            return Response({
                'session_id': payment_session.session_id,
                'qr_type': qr_code.qr_type,  # ✅ AJOUT
                'amount': float(amount),  # ✅ AJOUT - montant final utilisé
                'otp_sent': True,
                'message': f'Code OTP envoyé au {serializer.validated_data["phone_number"]}',
                'expires_in': 15
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    except QRCode.DoesNotExist:
        return Response({
            'error': 'QR Code introuvable'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_qr_otp_and_pay(request, session_id):
    """
    POST: Vérifier l'OTP et finaliser le paiement QR
    """
    try:
        payment_session = get_object_or_404(QRPaymentSession, session_id=session_id)
        
        if payment_session.status not in ['otp_sent', 'processing']:
            return Response({
                'error': 'Cette session de paiement ne peut plus être traitée'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if payment_session.is_expired():
            payment_session.status = 'expired'
            payment_session.save()
            return Response({
                'error': 'Session expirée'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = QRPaymentOTPVerifySerializer(data=request.data)
        
        if serializer.is_valid():
            otp_code = serializer.validated_data['otp_code']
            
            # Récupérer l'OTP le plus récent pour cette session
            try:
                qr_otp = payment_session.qr_otps.filter(
                    is_used=False
                ).order_by('-created_at').first()
                
                if not qr_otp:
                    return Response({
                        'error': 'Aucun code OTP valide trouvé'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                if qr_otp.is_expired():
                    return Response({
                        'error': 'Code OTP expiré'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Vérifier l'OTP (1234 pour test)
                if otp_code == qr_otp.code or otp_code == '1234':
                    # Marquer l'OTP comme utilisé
                    qr_otp.is_used = True
                    qr_otp.save()
                    
                    # Mettre à jour la session
                    payment_session.status = 'processing'
                    payment_session.save()
                    
                    # Créer la transaction
                    from decimal import Decimal
                    transaction_obj = Transaction.objects.create(
                        payment_session=payment_session,
                        transaction_type='payment',
                        sender_wallet_phone=payment_session.customer_wallet_phone,
                        sender_wallet_provider=qr_otp.wallet_provider,
                        merchant=payment_session.merchant,
                        amount=payment_session.amount,
                        currency=payment_session.currency,
                        fee_amount=Decimal('0'),  # Pas de frais pour QR direct
                        description=f"Paiement QR: {payment_session.qr_code.name}",
                        status='completed',
                        completed_at=timezone.now()
                    )
                    
                    # Finaliser la session
                    payment_session.status = 'completed'
                    payment_session.completed_at = timezone.now()
                    payment_session.save()
                    
                    # Mettre à jour les statistiques du QR code
                    qr_code = payment_session.qr_code
                    qr_code.total_revenue += payment_session.amount
                    qr_code.save()
                    
                    return Response({
                        'success': True,
                        'session_id': payment_session.session_id,
                        'transaction_id': transaction_obj.transaction_id,
                        'amount': payment_session.amount,
                        'currency': payment_session.currency,
                        'merchant_name': payment_session.merchant.business_name or payment_session.merchant.nom_complet,
                        'message': 'Paiement effectué avec succès'
                    })
                else:
                    return Response({
                        'error': 'Code OTP invalide'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
            except Exception as e:
                print(f"Error during OTP verification: {e}")
                return Response({
                    'error': 'Erreur lors de la vérification OTP'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    except QRPaymentSession.DoesNotExist:
        return Response({
            'error': 'Session de paiement introuvable'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def qr_payments_history(request):
    """
    GET: Historique des paiements QR du merchant
    """
    if request.user.user_type != 'merchant':
        return Response({'error': 'Accès reservé aux merchants'}, status=status.HTTP_403_FORBIDDEN)
    
    qr_codes = QRCode.objects.filter(merchant=request.user)
    qr_sessions = QRPaymentSession.objects.filter(
        qr_code__in=qr_codes,
        status='completed'
    ).order_by('-completed_at')
    
    serializer = QRPaymentSessionSerializer(qr_sessions, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_wallet_providers(request):
    """
    GET: Liste des portefeuilles supportés
    """
    providers = WalletProvider.objects.filter(is_active=True)
    data = []
    
    for provider in providers:
        data.append({
            'id': provider.name,
            'name': provider.display_name,
            'logo_url': provider.logo_url,
            'supports_otp': provider.supports_otp
        })
    
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def qr_code_stats(request):
    """
    GET: Statistiques des QR codes du merchant
    """
    if request.user.user_type != 'merchant':
        return Response({'error': 'Accès reservé aux merchants'}, status=status.HTTP_403_FORBIDDEN)
    
    user_qr_codes = QRCode.objects.filter(merchant=request.user)
    
    stats = {
        'total_qrs': user_qr_codes.count(),
        'active_qrs': user_qr_codes.filter(status='active').count(),
        'total_scans': user_qr_codes.aggregate(Sum('scans_count'))['scans_count__sum'] or 0,
        'total_revenue': user_qr_codes.aggregate(Sum('total_revenue'))['total_revenue__sum'] or 0
    }
    
    return Response(stats)
    """
    GET: Liste des portefeuilles supportés
    """
    providers = WalletProvider.objects.filter(is_active=True)
    data = []
    
    for provider in providers:
        data.append({
            'id': provider.name,
            'name': provider.display_name,
            'logo_url': provider.logo_url,
            'supports_otp': provider.supports_otp
        })
    
    return Response(data)


