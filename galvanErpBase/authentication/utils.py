import random
import string
from django.core.mail import send_mail
from django.conf import settings
import requests
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

def send_email_otp(user, otp):
    subject = 'Email Verification OTP'
    message = f'Your OTP for email verification is: {otp}\nThis OTP will expire in 10 minutes.'
    try:
        send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )
        logger.info(f"Successfully sent email OTP to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email OTP to {user.email}: {str(e)}")
        return False

def send_phone_otp(user, otp):
    if not user.phone_number:
        logger.error("Attempted to send phone OTP but no phone number provided")
        return False
        
    try:
        headers = {
            'Authorization': f'Bearer {settings.TEXTLK_API_TOKEN}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        payload = {
            'message': f'Your OTP for phone verification is: {otp}\nThis OTP will expire in 10 minutes.',
            'recipient': user.phone_number,
            'sender_id': 'TextLKDemo',  # Default sender ID for Text.lk
            'type': 'plain',
        }
        
        resp = requests.post(
            f'{settings.TEXTLK_API_URL}send',
            json=payload,
            headers=headers,
            timeout=10
        )
        
        response_data = resp.json()
        if resp.status_code == 200 and response_data.get('status') == 'success':
            logger.info(f"Successfully sent phone OTP to {user.phone_number}")
            return True
        else:
            logger.error(f"Text.lk SMS service error for {user.phone_number}: {response_data.get('message', 'Unknown error')}")
            return False
    except requests.RequestException as e:
        logger.error(f"Failed to send phone OTP to {user.phone_number}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending phone OTP to {user.phone_number}: {str(e)}")
        return False

def can_request_otp(user):
    """Check if user can request new OTP based on rate limit"""
    if not user.last_otp_time:
        logger.info(f"First OTP request for user {user.id}")
        return True
    
    if user.otp_attempts >= settings.MAX_OTP_ATTEMPTS:
        cooldown_period = timezone.now() - user.last_otp_time
        if cooldown_period < timedelta(minutes=settings.OTP_COOLDOWN_MINUTES):
            logger.warning(f"User {user.id} exceeded OTP attempts. Cooldown active")
            return False
        # Reset attempts after cooldown
        user.otp_attempts = 0
        user.save()
        logger.info(f"Reset OTP attempts for user {user.id} after cooldown")
    return True