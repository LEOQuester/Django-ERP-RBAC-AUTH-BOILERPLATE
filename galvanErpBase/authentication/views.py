from django.shortcuts import render, get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password, ValidationError
from django.core.mail import send_mail
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from datetime import datetime, timedelta
from .serializers import (
    UserRegistrationSerializer, OTPVerificationSerializer,
    LoginSerializer, UserVerificationStatusSerializer, UserUpdateSerializer
)
from .utils import send_email_otp, send_phone_otp, can_request_otp
from .models import OTPVerification, User
import random
import string
import logging

logger = logging.getLogger(__name__)

class RegistrationRateThrottle(AnonRateThrottle):
    rate = '5/hour'  # Allow 100 registrations per second

class OTPRateThrottle(UserRateThrottle):
    rate = '10/hour'

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([RegistrationRateThrottle])
def register_user(request):
    try:
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            response_data = {
                'message': 'Registration successful.',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'phone_number': user.phone_number,
                }
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return Response(
            {'error': 'An unexpected error occurred during registration'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([OTPRateThrottle])
def verify_otp(request):
    try:
        serializer = OTPVerificationSerializer(data=request.data, context={'user': request.user})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        if not can_request_otp(user):
            cooldown_minutes = 10 - (timezone.now() - user.last_otp_time).minutes
            return Response({
                'error': f'Too many attempts. Please wait {cooldown_minutes} minutes before trying again.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        verification_type = serializer.validated_data['verification_type']
        otp = serializer.validated_data['otp']
        otp_record = serializer.validated_data['otp_record']

        if otp_record.otp != otp:
            otp_record.attempts += 1
            user.otp_attempts += 1
            user.last_otp_time = timezone.now()
            otp_record.save()
            user.save()
            
            remaining_attempts = 6 - user.otp_attempts
            if remaining_attempts > 0:
                return Response({
                    'error': f'Invalid OTP. {remaining_attempts} attempts remaining.'
                }, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                'error': 'Maximum attempts reached. Please wait 10 minutes before trying again.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        # OTP is valid
        if verification_type == 'EMAIL':
            user.is_email_verified = True
        else:
            user.is_phone_verified = True

        otp_record.is_verified = True
        otp_record.save()
        user.save()

        return Response({
            'message': f'{verification_type.lower()} verified successfully',
            'is_email_verified': user.is_email_verified,
            'is_phone_verified': user.is_phone_verified,
            'is_verified': user.is_verified
        })
    except Exception as e:
        logger.error(f"OTP verification error: {str(e)}")
        return Response(
            {'error': 'An unexpected error occurred during verification'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([OTPRateThrottle])
def resend_otp(request):
    try:
        verification_type = request.data.get('verification_type')
        if not verification_type or verification_type not in ['EMAIL', 'PHONE']:
            return Response({
                'error': 'Invalid verification type'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        if verification_type == 'EMAIL' and user.is_email_verified:
            return Response({
                'error': 'Email is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)
        if verification_type == 'PHONE' and user.is_phone_verified:
            return Response({
                'error': 'Phone number is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not can_request_otp(user):
            cooldown_minutes = 10 - (timezone.now() - user.last_otp_time).minutes
            return Response({
                'error': f'Too many attempts. Please wait {cooldown_minutes} minutes before trying again.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        new_otp = ''.join(random.choices(string.digits, k=6))
        OTPVerification.objects.create(
            user=user,
            otp=new_otp,
            verification_type=verification_type
        )

        success = False
        if verification_type == 'EMAIL':
            success = send_email_otp(user, new_otp)
        else:
            success = send_phone_otp(user, new_otp)

        if not success:
            return Response({
                'error': f'Failed to send OTP to your {verification_type.lower()}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            'message': f'New OTP sent to your {verification_type.lower()}'
        })
    except Exception as e:
        logger.error(f"Resend OTP error: {str(e)}")
        return Response(
            {'error': 'An unexpected error occurred while sending OTP'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            response = JsonResponse({
                'user': {
                    'name': user.get_full_name(),
                    'is_verified': user.is_verified,
                    'profile_pic': user.profile_pic.url if user.profile_pic else None
                },
                'access_token': access_token
            })

            response.set_cookie(
                'refresh_token',
                str(refresh),
                httponly=True,
                secure=settings.SESSION_COOKIE_SECURE,
                samesite='Lax',
                max_age=7 * 24 * 60 * 60  # 7 days
            )

            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@method_decorator(csrf_exempt, name='dispatch')
class CookieTokenRefreshView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            return Response({
                'error': 'No refresh token provided'
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            response = Response({
                'access_token': access_token
            })

            # Update refresh token
            response.set_cookie(
                'refresh_token',
                str(refresh),
                httponly=True,
                secure=settings.SESSION_COOKIE_SECURE,
                samesite='Lax',
                max_age=7 * 24 * 60 * 60
            )
            
            return response

        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    def post(self, request):
        response = Response({'message': 'Logged out successfully'})
        response.delete_cookie('refresh_token')
        return response

def generate_reset_token(user):
    """Generate a JWT token for password reset"""
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'type': 'password_reset'
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

def verify_reset_token(token):
    """Verify the password reset token"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        if payload['type'] != 'password_reset':
            return None
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        User = get_user_model()
        email = request.data.get("email")
        
        try:
            user = User.objects.get(email=email)
            token = generate_reset_token(user)
            reset_link = f"{request.data.get('frontend_url', 'http://localhost:4200')}/reset-password?token={token}"
            
            send_mail(
                "Reset your password",
                f"Click this link to reset your password: {reset_link}",
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return Response({
                "message": "Reset link sent to your email"
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                "message": "If an account exists with this email, a reset link will be sent."
            }, status=status.HTTP_200_OK)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        token = request.data.get("token")
        new_password = request.data.get("new_password")
        User = get_user_model()

        if not token or not new_password:
            return Response({
                "error": "Token and new password are required"
            }, status=status.HTTP_400_BAD_REQUEST)

        user_id = verify_reset_token(token)
        if not user_id:
            return Response({
                "error": "Invalid or expired token"
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            
            # Validate password
            try:
                validate_password(new_password, user)
            except ValidationError as e:
                return Response({
                    "error": e.messages
                }, status=status.HTTP_400_BAD_REQUEST)

            user.password = make_password(new_password)
            user.save()

            return Response({
                "message": "Password updated successfully"
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                "error": "User not found"
            }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([OTPRateThrottle])
def send_email_verification(request):
    try:
        user = request.user
        if user.is_email_verified:
            return Response({
                'error': 'Email is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not can_request_otp(user):
            cooldown_minutes = 10 - (timezone.now() - user.last_otp_time).minutes
            return Response({
                'error': f'Too many attempts. Please wait {cooldown_minutes} minutes before trying again.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        # Generate new OTP
        email_otp = ''.join(random.choices(string.digits, k=6))
        OTPVerification.objects.create(
            user=user,
            otp=email_otp,
            verification_type='EMAIL'
        )
        
        # Send OTP
        if send_email_otp(user, email_otp):
            return Response({
                'message': 'Email verification OTP sent successfully'
            })
        return Response({
            'error': 'Failed to send email OTP'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.error(f"Email OTP sending error: {str(e)}")
        return Response({
            'error': 'An unexpected error occurred'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([OTPRateThrottle])
def send_phone_verification(request):
    try:
        user = request.user
        if not user.phone_number:
            return Response({
                'error': 'No phone number associated with this account'
            }, status=status.HTTP_400_BAD_REQUEST)

        if user.is_phone_verified:
            return Response({
                'error': 'Phone number is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not can_request_otp(user):
            cooldown_minutes = 10 - (timezone.now() - user.last_otp_time).minutes
            return Response({
                'error': f'Too many attempts. Please wait {cooldown_minutes} minutes before trying again.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)

        # Generate new OTP
        phone_otp = ''.join(random.choices(string.digits, k=6))
        OTPVerification.objects.create(
            user=user,
            otp=phone_otp,
            verification_type='PHONE'
        )
        
        # Send OTP
        if send_phone_otp(user, phone_otp):
            return Response({
                'message': 'Phone verification OTP sent successfully'
            })
        return Response({
            'error': 'Failed to send phone OTP'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.error(f"Phone OTP sending error: {str(e)}")
        return Response({
            'error': 'An unexpected error occurred'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_verification_status(request):
    """
    Get the verification status of the currently logged in user.
    This endpoint can be accessed by both verified and unverified users.
    """
    serializer = UserVerificationStatusSerializer(request.user)
    return Response(serializer.data)

class UserUpdateDelete(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get user's own profile"""
        serializer = UserUpdateSerializer(request.user)
        return Response(serializer.data)

    def patch(self, request):
        """Update user's own profile"""
        serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """Soft delete user's own account"""
        user = request.user
        user.is_deleted = True
        user.is_active = False
        user.save()
        return Response({"message": "Account successfully deleted"}, status=status.HTTP_200_OK)

class AdminUserManage(APIView):
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """Only allow admin users to access this view"""
        if self.request.method in ['GET', 'PATCH', 'DELETE']:
            return [IsAuthenticated()]
        return super().get_permissions()

    def get(self, request, user_id):
        """Get any user's profile (admin only)"""
        if not request.user.is_staff:
            return Response({"error": "Admin access required"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(id=user_id)
            serializer = UserUpdateSerializer(user)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, user_id):
        """Update any user's profile (admin only)"""
        if not request.user.is_staff:
            return Response({"error": "Admin access required"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(id=user_id)
            serializer = UserUpdateSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, user_id):
        """Soft delete any user's account (admin only)"""
        if not request.user.is_staff:
            return Response({"error": "Admin access required"}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(id=user_id)
            user.is_deleted = True
            user.is_active = False
            user.save()
            return Response({"message": "Account successfully deleted"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
