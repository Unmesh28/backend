from django.conf import settings
from django.core.mail import send_mail

from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

from accounts.models import User


twilio_account_sid = settings.TWILIO_ACCOUNT_SID
twilio_auth_token = settings.TWILIO_AUTH_TOKEN
twilio_phone_number = settings.TWILIO_PHONE_NUMBER


def send_notification(user:User, message:str) -> None:
    
    if '@' in user.username:
        # send email
        send_mail(
            'Innovative Instruments App',
            message,
            settings.EMAIL_HOST_USER,
            [user.username]
        )
    else:
        # send SMS
        if all(
            [
                twilio_account_sid,
                twilio_auth_token,
                twilio_phone_number
            ]
        ):
            try:
                twilio_client = Client(
                    twilio_account_sid, twilio_auth_token
                )
                twilio_client.messages.create(
                    body=message,
                    to=str(user.username),
                    from_=twilio_phone_number,
                )

                return True
            except TwilioRestException as e:
                print(e)
        else:
            print("Twilio credentials are not set")

def welcome_notification(user:User) -> None:
    message = f"Welcome to Innovative Instruments Application. Your User ID is: {user.username}."

    send_notification(
        user,
        message,
    )

def change_password_notification(user:User) -> None:
    message = """
        Your password has been changed for the Innovative Instruments Application.
        If it is not you who has changed the password, please contact +91 12345678.
        """

    send_notification(
        user,
        message,
    )

def otp_notification(user:User) -> None:
    message = f"""
            The OTP to login into the Innovative Instruments application is {user.otp}.
            This OTP shall expire after {settings.TOKEN_EXPIRE_MINUTES} minutes at: {user.otp_expired_at}.
            """

    send_notification(
        user,
        message
    )
