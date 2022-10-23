from django.db import models
from django.utils.translation import gettext as _
from django.conf import settings
from django.utils.crypto import get_random_string
from django.contrib.auth.models import AbstractUser


# Extended User Class
class User(AbstractUser):
    email = None
    otp = models.CharField(max_length=120, null=True, blank=True)
    otp_expired_at = models.DateTimeField(null=True, blank=True)
    password_expired_at = models.DateTimeField(null=True)

    REQUIRED_FIELDS = []

    def generate_security_code(self):
        """
        Returns a unique random `security_code` for given `TOKEN_LENGTH` in the settings.
        Default token length = 6
        """
        token_length = getattr(settings, "TOKEN_LENGTH", 6)
        return get_random_string(int(token_length), allowed_chars="0123456789")

    # def is_security_code_expired(self):
    #     expiration_date = self.sent + datetime.timedelta(
    #         minutes=settings.TOKEN_EXPIRE_MINUTES
    #     )
    #     return expiration_date <= timezone.now()

    # def check_verification(self, security_code):
    #     if (
    #         not self.is_security_code_expired() and
    #         security_code == self.security_code and
    #         self.is_verified == False
    #     ):
    #         self.is_verified = True
    #         self.save()
    #     else:
    #         raise NotAcceptable(
    #             _("Your security code is wrong, expired or this phone is verified before."))

    #     return self.is_verified
