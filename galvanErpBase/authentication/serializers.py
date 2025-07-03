from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.hashers import check_password
from django.db.models import Q
import re
from .models import OTPVerification

User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    profile_pic = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email', 'first_name', 'last_name',
                 'phone_number', 'nic', 'gender', 'address', 'dob', 'profile_pic')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'gender': {'required': True},
            'dob': {'required': True},
            'nic': {'required': False}
        }

    def validate_nic(self, value):
        if value and User.objects.filter(nic=value, is_deleted=False).exists():
            raise serializers.ValidationError("User with this NIC already exists.")
        return value

    def validate_phone_number(self, value):
        if value:
            # Validates international phone numbers
            pattern = r'^\+?1?\d{9,15}$'
            if not re.match(pattern, value):
                raise serializers.ValidationError(
                    "Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
                )
        return value

    def validate_profile_pic(self, value):
        if value:
            if value.size > settings.MAX_UPLOAD_SIZE:
                raise serializers.ValidationError(
                    f"Image size should not exceed {settings.MAX_UPLOAD_SIZE/1024/1024}MB"
                )
            if value.content_type not in settings.ALLOWED_IMAGE_TYPES:
                raise serializers.ValidationError(
                    f"Image type not supported. Allowed types: {', '.join(settings.ALLOWED_IMAGE_TYPES)}"
                )
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        # Check if a non-deleted user exists with this email, username, or phone
        email = attrs.get('email')
        username = attrs.get('username')
        phone_number = attrs.get('phone_number')
        
        # For email - only check non-deleted users
        if User.objects.filter(email=email, is_deleted=False).exists():
            raise serializers.ValidationError({"email": "User with this email already exists."})
        
        # For username - only check non-deleted users
        if User.objects.filter(username=username, is_deleted=False).exists():
            raise serializers.ValidationError({"username": "User with this username already exists."})
        
        # For phone number - only check non-deleted users
        if phone_number and User.objects.filter(phone_number=phone_number, is_deleted=False).exists():
            raise serializers.ValidationError({"phone_number": "User with this phone number already exists."})
        
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        password = validated_data.pop('password')
        
        
        # Create new user
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user

class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, min_length=6)
    verification_type = serializers.ChoiceField(choices=['EMAIL', 'PHONE'])

    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits")
        return value

    def validate(self, attrs):
        user = self.context.get('user')
        verification_type = attrs['verification_type']

        # Check if already verified
        if verification_type == 'EMAIL' and user.is_email_verified:
            raise serializers.ValidationError({"verification_type": "Email is already verified"})
        if verification_type == 'PHONE' and user.is_phone_verified:
            raise serializers.ValidationError({"verification_type": "Phone number is already verified"})

        # Get latest OTP record
        otp_record = OTPVerification.objects.filter(
            user=user,
            verification_type=verification_type,
            is_verified=False
        ).order_by('-created_at').first()

        if not otp_record:
            raise serializers.ValidationError({"otp": "No active OTP found"})

        if otp_record.expires_at < timezone.now():
            raise serializers.ValidationError({"otp": "OTP has expired"})

        attrs['otp_record'] = otp_record
        return attrs

class LoginSerializer(serializers.Serializer):
    username_or_email_or_phone = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        identifier = data.get('username_or_email_or_phone')
        password = data.get('password')

        if not identifier or not password:
            raise serializers.ValidationError({
                'error': 'Both identifier and password are required.'
            })

        # E.164 phone number format validation
        e164_pattern = re.compile(r'^\+?[1-9]\d{1,14}$')        # Try to find non-deleted user by email, phone, or username
        if '@' in identifier:
            user = User.objects.filter(email=identifier, is_deleted=False).first()
        elif e164_pattern.match(identifier):
            user = User.objects.filter(phone_number=identifier, is_deleted=False).first()
        else:
            user = User.objects.filter(username=identifier, is_deleted=False).first()

        if not user:
            raise serializers.ValidationError({
                'error': 'No account found with these credentials.'
            })

        if not user.check_password(password):
            raise serializers.ValidationError({
                'error': 'Invalid credentials.'
            })

        if not user.is_active:
            raise serializers.ValidationError({
                'error': 'This account has been deactivated.'
            })
        
        # Update last login
        user.save(update_fields=['last_login'])
        
        data['user'] = user
        return data

class UserVerificationStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('is_email_verified', 'is_phone_verified', 'is_verified')
        read_only_fields = fields

class UserUpdateSerializer(serializers.ModelSerializer):    
    profile_pic = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'phone_number', 'nic',
                 'gender', 'address', 'dob', 'profile_pic', 'date_joined', 'last_modified', 
                 'is_active', 'is_email_verified', 'is_phone_verified', 'is_verified')
        read_only_fields = ('id', 'date_joined', 'last_modified', 
                          'is_active', 'is_email_verified', 'is_phone_verified', 'is_verified')
        extra_kwargs = {
            'username': {'required': False},
            'phone_number': {'required': False},
            'gender': {'required': False},
            'dob': {'required': False},
            'email': {'required': False},
            'nic': {'required': False}
        }

    def validate_username(self, value):
        if value:
            if User.objects.filter(username=value).exclude(id=self.instance.id).exclude(is_deleted=True).exists():
                raise serializers.ValidationError("This username is already in use.")
            if not value.isalnum():
                raise serializers.ValidationError("Username can only contain letters and numbers.")
            if len(value) < 3:
                raise serializers.ValidationError("Username must be at least 3 characters long.")
            if len(value) > 30:
                raise serializers.ValidationError("Username cannot be more than 30 characters long.")
        return value

    def validate_nic(self, value):
        if value:
            if User.objects.filter(nic=value).exclude(id=self.instance.id).exclude(is_deleted=True).exists():
                raise serializers.ValidationError("This NIC is already in use.")
        return value

    def validate_phone_number(self, value):
        if value:
            pattern = r'^\+?1?\d{9,15}$'
            if not re.match(pattern, value):
                raise serializers.ValidationError(
                    "Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
                )
            if User.objects.filter(phone_number=value).exclude(id=self.instance.id).exclude(is_deleted=True).exists():
                raise serializers.ValidationError("This phone number is already in use.")
        return value

    def validate_email(self, value):
        if value:
            if User.objects.filter(email=value).exclude(id=self.instance.id).exclude(is_deleted=True).exists():
                raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_profile_pic(self, value):
        if value:
            if value.size > settings.MAX_UPLOAD_SIZE:
                raise serializers.ValidationError(
                    f"Image size should not exceed {settings.MAX_UPLOAD_SIZE/1024/1024}MB"
                )
            if value.content_type not in settings.ALLOWED_IMAGE_TYPES:
                raise serializers.ValidationError(
                    f"Image type not supported. Allowed types: {', '.join(settings.ALLOWED_IMAGE_TYPES)}"
                )
        return value

    def update(self, instance, validated_data):
        if 'email' in validated_data and validated_data['email'] != instance.email:
            instance.is_email_verified = False
            instance.is_verified = False
        if 'phone_number' in validated_data and validated_data['phone_number'] != instance.phone_number:
            instance.is_phone_verified = False
            instance.is_verified = False
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance