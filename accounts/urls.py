from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    ForgetPasswordView,
    LogoutView,
    PasswordChangeView,
    PasswordResetView,
    UserLoginAPIView,
    UserRegisterationAPIView,
)

app_name = 'accounts'

router = DefaultRouter()

urlpatterns = [
    path('register/', UserRegisterationAPIView.as_view(), name='user_register'),
    path('login/', UserLoginAPIView.as_view(), name='user_login'),
    path('password/change/', PasswordChangeView.as_view(), name='password_change'),
    path('forget_password/', ForgetPasswordView.as_view(), name='forget_password'),
    path('reset_password/', PasswordResetView.as_view(), name='reset_password'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
