"""
Chinguisoft SMS OTP Integration Utilities
"""
import requests
import random
from django.conf import settings
from django.utils.timezone import now, timedelta
from .models import PaymentOTP, WalletVerificationOTP


def format_mauritanian_phone(phone_number):
    """
    Format Mauritanian phone number for Chinguisoft API
    Removes country code and formatting to get 8-digit number
    
    Examples:
        +22234503710 -> 34503710
        22234503710 -> 34503710
        34503710 -> 34503710
    """
    # Remove all non-digit characters
    digits_only = ''.join(filter(str.isdigit, phone_number))
    
    # Remove Mauritanian country code (222) if present
    if digits_only.startswith('222') and len(digits_only) == 11:
        return digits_only[3:]  # Remove first 3 digits (222)
    elif len(digits_only) == 8:
        return digits_only  # Already in correct format
    else:
        # Return as-is and let Chinguisoft handle validation
        return digits_only


def send_chinguisoft_otp(phone_number, lang='ar'):
    """
    Send OTP via Chinguisoft SMS service
    
    Args:
        phone_number (str): The phone number to send OTP to (will be auto-formatted)
        lang (str): Language for the SMS ('ar' for Arabic, 'fr' for French)
    
    Returns:
        str or None: The OTP code if successful, None if failed
    """
    # Format phone number for Chinguisoft
    formatted_phone = format_mauritanian_phone(phone_number)
    
    url = f"https://chinguisoft.com/api/sms/validation/{settings.CHINGUISOFT_VALIDATION_KEY}"
    headers = {
        'Validation-token': settings.CHINGUISOFT_TOKEN,
        'Content-Type': 'application/json',
    }
    data = {
        'phone': formatted_phone,
        'lang': lang
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response_data = response.json()
        
        if response.status_code == 200 and "code" in response_data:
            otp_code = response_data["code"]
            print(f"✅ Chinguisoft OTP sent successfully to {phone_number} (formatted: {formatted_phone}): {otp_code}")
            return otp_code
        else:
            print(f"❌ Chinguisoft API error: {response_data}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Chinguisoft OTP request failed: {str(e)}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error sending OTP: {str(e)}")
        return None


def send_payment_otp_chinguisoft(phone_number, payment_session, lang='ar'):
    """
    Send payment OTP using Chinguisoft and store in database
    
    Args:
        phone_number (str): Phone number to send OTP to
        payment_session: PaymentSession instance
        lang (str): Language for SMS
    
    Returns:
        str or None: OTP code if successful, None if failed
    """
    # Get OTP from Chinguisoft
    otp_code = send_chinguisoft_otp(phone_number, lang)
    
    if otp_code:
        # Delete existing OTPs for this session
        PaymentOTP.objects.filter(payment_session=payment_session).delete()
        
        # Create new OTP record
        PaymentOTP.objects.create(
            payment_session=payment_session,
            phone_number=phone_number,
            code=otp_code,
            purpose='transaction'
        )
        
        return otp_code
    
    return None


def send_wallet_verification_otp_chinguisoft(phone_number, wallet_verification, lang='ar'):
    """
    Send wallet verification OTP using Chinguisoft and store in database
    
    Args:
        phone_number (str): Phone number to send OTP to
        wallet_verification: WalletVerificationOTP instance
        lang (str): Language for SMS
    
    Returns:
        str or None: OTP code if successful, None if failed
    """
    # Get OTP from Chinguisoft
    otp_code = send_chinguisoft_otp(phone_number, lang)
    
    if otp_code:
        # Update the wallet verification record with the OTP
        wallet_verification.code = otp_code
        wallet_verification.save()
        
        return otp_code
    
    return None


def generate_fallback_otp():
    """
    Generate a fallback OTP if Chinguisoft fails
    This is for development/testing purposes
    """
    return str(random.randint(100000, 999999))