from django.utils import timezone
from typing import Dict
from django.utils.translation import gettext as _
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import permissions, status
from rest_framework.views import APIView

from accounts.models import User 
from accounts.serializers import (
    ForgetPasswordSerializer,
    LogoutSerializer,
    PasswordChangeSerializer,
    PasswordResetSerializer,
    UserLoginSerializer,
    UserRegistrationSerializer
)


def get_tokens_for_user(user:User) -> Dict:
        refresh_token = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh_token),
            'access': str(refresh_token.access_token),
        }


class UserRegisterationAPIView(GenericAPIView):
    """
    Register new users using phone number or email and password.
    """
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({
            "user": UserRegistrationSerializer(user, context=self.get_serializer_context()).data,
            "token": get_tokens_for_user(user)
            }, status=status.HTTP_200_OK)


class UserLoginAPIView(GenericAPIView):
    """
    Authenticate existing users using phone number or email and password.
    """
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.get(username=request.data['user_id'], is_active=True)
        user.last_login = timezone.now()
        user.save()

        return Response({
            "user": serializer.data,
            "token": get_tokens_for_user(user)
            }, status=status.HTTP_200_OK)


class PasswordChangeView(GenericAPIView):
    """
    Change password using user id and current password.

    Accepts the following POST parameters: password, verify_password
    Returns the success/fail message.
    """
    serializer_class = PasswordChangeSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response(
            {
                'detail': _('New password has been saved.'),
                'token': get_tokens_for_user(user)
            }, 
            status=status.HTTP_201_CREATED)


class ForgetPasswordView(GenericAPIView):
    """
    Accepts the following POST parameters: user id
    Returns the success/fail message.
    """
    serializer_class = ForgetPasswordSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.save()
        # Return the success message with OK HTTP status
        return Response(
            {'detail': _('OTP has been sent.')},
            status=status.HTTP_200_OK,
        )
        

class PasswordResetView(GenericAPIView):
    """
    Reset password using user id and otp.

    Accepts the following POST parameters: password, verify_password
    Returns the success/fail message.
    """
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response(
            {
                'detail': _('New password has been saved.'),
                'token': get_tokens_for_user(user)
            }, 
            status=status.HTTP_201_CREATED)


class LogoutView(APIView):
    """
    Logout an authenticated user.
    """
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"message": "The refresh token blacklisted"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            print(e)
            return Response(status=status.HTTP_400_BAD_REQUEST)

