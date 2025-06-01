from django.urls import path
from .views import (
    RegisterView, LoginView, ProfileView,
    VerifyEmailView, RequestPasswordResetView, ResetPasswordView,
    VerifyEmailLinkView, ResetPasswordLinkView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    # Handle email verification both ways
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),  # POST with token in body
    path('verify-email/<str:token>/', VerifyEmailLinkView.as_view(), name='verify-email-link'),  # GET with token in URL
    # Handle password reset both ways
    path('request-password-reset/', RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),  # POST with token in body
    path('reset-password/<str:token>/', ResetPasswordLinkView.as_view(), name='reset-password-link'),  # GET with token in URL
]
