from pyexpat import model
import phonenumbers
from datetime import timedelta
from django.utils.translation import gettext as _
from django.contrib.auth import authenticate
from django.conf import settings
from django.core.validators import EmailValidator
from django.core import exceptions
import django.contrib.auth.password_validation as validators
from django.utils import timezone
from rest_framework import serializers
from accounts.exceptions import (
    AccountDisabledException,
    AccountNotRegisteredException,
    ExistUserException,
    IncorrectOTPException, 
    InvalidCredentialsException,
    InvalidUserIdException,
    OtpExpiredException, 
    PasswordExpiredException,
    RequiredException
)

from accounts.models import User
from accounts.notifications import (
    change_password_notification,
    otp_notification, 
    welcome_notification
)


def validate_password(user, password):
    errors = dict() 
    try:
        # validate the password and catch the exception
        validators.validate_password(password=password, user=user)
    
    # the exception raised here is different than serializers.ValidationError
    except exceptions.ValidationError as e:
        errors['password'] = list(e.messages)
    
    if errors:
        raise serializers.ValidationError(errors)

    return password

class UserRegistrationSerializer(serializers.Serializer):
    """
    Serializer for registrating new users using userid.
    User id can be email or phone number.
    """
    user_id = serializers.CharField(source='username', required=False)
    password = serializers.CharField(write_only=True, style={'input_type': 'password'}, required=False)
    verify_password = serializers.CharField(write_only=True, style={'input_type': 'password'}, required=False)

    def _validate_user(self, user_id):

        if '@' in user_id:
            # the validation for email should be done here
            validator = EmailValidator()
            validator(user_id)
        else:
            # here the phone number should be validated
            try:
                z = phonenumbers.parse(user_id, None)
                if not phonenumbers.is_valid_number(z):
                    raise InvalidUserIdException()
            except Exception as e:
                raise InvalidUserIdException()

        # Unique validation
        user = User.objects.filter(username__iexact=user_id).exists()
        if user:
            raise ExistUserException()

        return user_id

    def validate(self, validated_data):
        user_id = validated_data.get('username', None)
        password = validated_data.get('password', None)
        verify_password = validated_data.get('verify_password', None)

        if not user_id:
            raise RequiredException()

        if not password:
            raise RequiredException()

        if not verify_password:
            raise RequiredException()

        # validate user id
        self._validate_user(user_id)

        # validate password
        user = User(username=validated_data['username'], password=validated_data['username'])
        validate_password(user, password)
        
        if validated_data['password'] != validated_data['verify_password']:
            raise serializers.ValidationError(
                _("The Password and Verify Password do not match. Please enter again."))

        return validated_data

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
        )

        user.set_password(validated_data['password'])
        user.password_expired_at = timezone.now() + timedelta(days=int(settings.PASSWORD_EXPIRE_DAYS))
        user.save()

        # send notification via email or SMS
        welcome_notification(user)

        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer to login users with user id and password.
    """
    user_id = serializers.CharField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def _validate_user(self, user_id, password):
        user = None

        if user_id and password:
            user = authenticate(username=user_id, password=password)
        else:
            raise serializers.ValidationError(
                _("Enter a user id and password."))

        return user

    def validate(self, validated_data):
        user_id = validated_data.get('user_id')
        password = validated_data.get('password')

        user = None

        user = self._validate_user(user_id, password)

        if not user:
            raise InvalidCredentialsException()

        if not user.is_active:
            raise AccountDisabledException()

        if user.password_expired_at and user.password_expired_at < timezone.now():
            raise PasswordExpiredException

        validated_data['user'] = user
        return validated_data


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer to profile update of an existing users with first name and last name.
    """
    user_id = serializers.CharField(source='username', read_only=True)
    
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'user_id')


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer to change password with user id and current password.
    """
    user_id = serializers.CharField()
    current_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    verify_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def _validate_user(self, user_id, password):
        user = None

        if user_id and password:
            user = authenticate(username=user_id, password=password)
        else:
            raise serializers.ValidationError(
                _("Enter a user id and password."))

        return user

    def _validate_new_password(self, user, new_password):
        errors = dict() 
        try:
            # validate the password and catch the exception
            validators.validate_password(password=new_password, user=user)
        
        # the exception raised here is different than serializers.ValidationError
        except exceptions.ValidationError as e:
            errors['new_password'] = list(e.messages)
        
        if errors:
            raise serializers.ValidationError(errors)

        return new_password

    def validate(self, validated_data):
        user_id = validated_data.get('user_id')
        current_password = validated_data.get('current_password')
        new_password = validated_data.get('new_password')

        user = None

        user = self._validate_user(user_id, current_password)

        if not user:
            raise InvalidCredentialsException()

        if not user.is_active:
            raise AccountDisabledException()

        # validate password
        user = User(username=validated_data['user_id'], password=validated_data['new_password'])
        self._validate_new_password(user, new_password)

        if validated_data['new_password'] == validated_data['current_password']:
            raise serializers.ValidationError(
                _("The Current Password and New Password are same. Please enter new one."))
        
        if validated_data['new_password'] != validated_data['verify_password']:
            raise serializers.ValidationError(
                _("The New Password and Verify Password do not match. Please enter again."))

        validated_data['user'] = user
        return validated_data

    def create(self, validated_data):
        user = User.objects.get(
            username=validated_data['user_id'],
        )

        user.set_password(validated_data['new_password'])
        user.password_expired_at = timezone.now() + timedelta(days=int(settings.PASSWORD_EXPIRE_DAYS))
        user.save()

        # send notification via email or SMS
        change_password_notification(user)

        return user


class ForgetPasswordSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset email/sms.
    """
    user_id = serializers.CharField()

    def _validate_user(self, user_id):
        user = None

        if user_id:
            try:
                user = User.objects.get(username=user_id)
            except User.DoesNotExist:
                raise AccountNotRegisteredException()
        else:
            raise serializers.ValidationError(
                _("Enter a user id."))

        return user

    def validate(self, validated_data):
        user_id = validated_data.get('user_id')
        user = None
        user = self._validate_user(user_id)

        if not user.is_active:
            raise AccountDisabledException()

        validated_data['user'] = user
        return validated_data

    def create(self, validated_data):
        user = User.objects.get(username=validated_data['user_id'])
        user.otp = user.generate_security_code()
        user.otp_expired_at = timezone.now() + timedelta(minutes=int(settings.TOKEN_EXPIRE_MINUTES))
        user.save()

        # send notification via email or SMS
        otp_notification(user)

        return user


class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer to reset password with user id, otp, password and verify password.
    """
    user_id = serializers.CharField()
    otp = serializers.CharField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    verify_password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def _validate_otp(self, user_id, otp):
        user = None

        try:
            user = User.objects.get(username=user_id)

            if user.otp != otp:
                raise IncorrectOTPException()

            if user.otp_expired_at and user.otp_expired_at < timezone.now():
                raise OtpExpiredException()

        except User.DoesNotExist:
            raise AccountNotRegisteredException()

        return user

    def validate(self, validated_data):
        user_id = validated_data.get('user_id')
        otp = validated_data.get('otp')
        password = validated_data.get('password')

        user = None

        user = self._validate_otp(user_id, otp)

        if not user.is_active:
            raise AccountDisabledException()

        # validate password
        user = User(username=validated_data['user_id'], password=validated_data['password'])
        validate_password(user, password)
        
        if validated_data['password'] != validated_data['verify_password']:
            raise serializers.ValidationError(
                _("The Password and Verify Password do not match. Please enter again."))

        validated_data['user'] = user
        return validated_data

    def create(self, validated_data):
        user = User.objects.get(
            username=validated_data['user_id'],
        )

        user.set_password(validated_data['password'])
        user.otp = None
        user.password_expired_at = timezone.now() + timedelta(days=int(settings.PASSWORD_EXPIRE_DAYS))
        user.save()

        return user


class LogoutSerializer(serializers.Serializer):
    """
        Serializer for logout
    """
    refresh_token = serializers.CharField()
