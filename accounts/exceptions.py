from django.utils.translation import gettext as _
from rest_framework.exceptions import APIException


class AccountNotRegisteredException(APIException):
    status_code = 404
    default_detail = _('This user is not registered with us. Please enter a valid User ID.')
    default_code = 'non-registered-account'


class AccountDisabledException(APIException):
    status_code = 403
    default_detail = _('User account is disabled.')
    default_code = 'account-disabled'


class InvalidCredentialsException(APIException):
    status_code = 401
    default_detail = _('Wrong user id or password.')
    default_code = 'invalid-credentials'


class PasswordExpiredException(APIException):
    status_code = 403
    default_detail = _('Your password is expired. Please change the password.')
    default_code = 'password-expired'


class OtpExpiredException(APIException):
    status_code = 403
    default_detail = _('The OTP has expired. Please generate the OTP again.')
    default_code = 'otp-expired'

class IncorrectOTPException(APIException):
    status_code = 403
    default_detail = _('The OTP is incorrect. Please verify and enter again.')
    default_code = 'incorrect-otp'
