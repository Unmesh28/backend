from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext as _
from django.conf import settings
from django.utils import timezone
from django.utils.crypto import get_random_string

from accounts.managers import CustomUserManager


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=200, unique=True)
    name = models.CharField(max_length=200, blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    
    otp = models.CharField(max_length=120, null=True, blank=True)
    otp_expired_at = models.DateTimeField(null=True, blank=True)
    password_expired_at = models.DateTimeField(null=True)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.username

    def generate_security_code(self):
        """
        Returns a unique random `security_code` for given `TOKEN_LENGTH` in the settings.
        Default token length = 6
        """
        token_length = getattr(settings, "TOKEN_LENGTH", 6)
        return get_random_string(int(token_length), allowed_chars="0123456789")
