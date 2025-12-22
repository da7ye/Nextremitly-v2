# user/email_templates.py
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class NextremitlyEmailTemplates:
    """
    Professional email template system for Nextremitly OTP emails
    """
    
    @staticmethod
    def get_base_context():
        """Get common context variables for all email templates"""
        return {
            'company_name': 'Nextremitly',
            'company_tagline': 'Secure Payment Gateway',
            'company_location': 'Mauritania',
            'current_year': '2025',
            'support_email': 'support@nextremitly.com',
            'website_url': getattr(settings, 'FRONTEND_URL', 'https://nextremitly.com')
        }
    
    @staticmethod
    def render_verification_email(user_name, otp_code, email):
        """Render account verification email template"""
        context = NextremitlyEmailTemplates.get_base_context()
        context.update({
            'user_name': user_name,
            'otp_code': otp_code,
            'email': email,
            'template_type': 'verification',
            'expiry_minutes': 5
        })
        
        # Render HTML template
        html_content = render_to_string('emails/otp_verification.html', context)
        
        # Render plain text fallback
        text_content = render_to_string('emails/otp_verification.txt', context)
        
        return html_content, text_content
    
    @staticmethod
    def render_password_reset_email(user_name, otp_code, email):
        """Render password reset email template"""
        context = NextremitlyEmailTemplates.get_base_context()
        context.update({
            'user_name': user_name,
            'otp_code': otp_code,
            'email': email,
            'template_type': 'password_reset',
            'expiry_minutes': 5
        })
        
        html_content = render_to_string('emails/otp_password_reset.html', context)
        text_content = render_to_string('emails/otp_password_reset.txt', context)
        
        return html_content, text_content
    
    @staticmethod
    def render_transaction_email(user_name, otp_code, transaction_details):
        """Render transaction verification email template"""
        context = NextremitlyEmailTemplates.get_base_context()
        context.update({
            'user_name': user_name,
            'otp_code': otp_code,
            'transaction_details': transaction_details,
            'template_type': 'transaction',
            'expiry_minutes': 5
        })
        
        html_content = render_to_string('emails/otp_transaction.html', context)
        text_content = render_to_string('emails/otp_transaction.txt', context)
        
        return html_content, text_content
    
    @staticmethod
    def render_welcome_email(user_name, user_type):
        """Render welcome email after successful verification"""
        context = NextremitlyEmailTemplates.get_base_context()
        context.update({
            'user_name': user_name,
            'user_type': user_type,
            'login_url': f"{context['website_url']}/login",
            'dashboard_url': f"{context['website_url']}/dashboard"
        })
        
        html_content = render_to_string('emails/welcome.html', context)
        text_content = render_to_string('emails/welcome.txt', context)
        
        return html_content, text_content


def send_styled_email(subject, to_email, html_content, text_content, from_email=None):
    """
    Send email with both HTML and text content
    """
    if from_email is None:
        from_email = settings.DEFAULT_FROM_EMAIL
    
    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=from_email,
            to=[to_email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        return False


def send_otp_email(email, otp_code, purpose='verification', user_name=None, transaction_details=None):
    """
    Enhanced OTP email sender with beautiful HTML templates
    """
    try:
        # Get user name if not provided
        if not user_name:
            from .models import CustUser
            try:
                user = CustUser.objects.get(email=email)
                user_name = user.nom_complet or user.email.split('@')[0]
            except CustUser.DoesNotExist:
                user_name = email.split('@')[0]
        
        # Determine template and subject based on purpose
        if purpose == 'verification':
            subject = '🔒 Verify Your Nextremitly Account'
            html_content, text_content = NextremitlyEmailTemplates.render_verification_email(
                user_name, otp_code, email
            )
            
        elif purpose == 'password_reset':
            subject = '🔑 Reset Your Nextremitly Password'
            html_content, text_content = NextremitlyEmailTemplates.render_password_reset_email(
                user_name, otp_code, email
            )
            
        elif purpose == 'transaction':
            subject = '💳 Verify Your Nextremitly Transaction'
            html_content, text_content = NextremitlyEmailTemplates.render_transaction_email(
                user_name, otp_code, transaction_details or {}
            )
            
        else:
            # Fallback to simple template
            subject = f'Nextremitly Verification Code'
            html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2>Nextremitly Verification</h2>
                <p>Hello {user_name},</p>
                <p>Your verification code is: <strong>{otp_code}</strong></p>
                <p>This code expires in 5 minutes.</p>
            </div>
            """
            text_content = f"Hello {user_name},\n\nYour verification code is: {otp_code}\n\nThis code expires in 5 minutes."
        
        # Send the email
        return send_styled_email(subject, email, html_content, text_content)
        
    except Exception as e:
        logger.error(f"Failed to send OTP email: {str(e)}")
        return False


def send_welcome_email(email, user_name, user_type):
    """
    Send welcome email after successful account verification
    """
    try:
        subject = '🎉 Welcome to Nextremitly!'
        html_content, text_content = NextremitlyEmailTemplates.render_welcome_email(user_name, user_type)
        
        return send_styled_email(subject, email, html_content, text_content)
        
    except Exception as e:
        logger.error(f"Failed to send welcome email: {str(e)}")
        return False


# user/utils.py - Enhanced utility functions
import random
import string
from django.core.mail import send_mail
from django.conf import settings
from .email_templates import send_otp_email as send_styled_otp_email

def generate_otp():
    """Generate a 6-digit OTP code"""
    return ''.join(random.choices(string.digits, k=6))


def send_otp_email(email, otp_code, purpose='verification', user_name=None, transaction_details=None):
    """
    Enhanced OTP email sender - now uses beautiful HTML templates
    """
    return send_styled_otp_email(email, otp_code, purpose, user_name, transaction_details)


# Update your views.py to use the enhanced email system
# Replace the existing send_otp_email calls in your views with these:

# In BuyerRegistrationView and MerchantRegistrationView:
# email_sent = send_otp_email(buyer.email, otp_code, 'verification', buyer.nom_complet)

# In PasswordResetRequestView:
# email_sent = send_otp_email(email, otp_code, 'password_reset', user.nom_complet)

# In PaymentInitiateView (for transaction OTPs):
# send_otp_email(request.user.email, otp_code, 'transaction', request.user.nom_complet, {
#     'amount': payment_session.amount,
#     'currency': payment_session.currency,
#     'merchant_name': payment_session.merchant.business_name,
#     'transaction_id': f'NXT-{payment_session.session_id.hex[:8].upper()}'
# })