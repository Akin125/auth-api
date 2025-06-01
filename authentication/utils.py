from django.core.mail import send_mail
from django.conf import settings
from .models import EmailVerificationToken, PasswordResetToken
from django.utils import timezone

def send_verification_email(user):
    """
    Create a verification token and send verification email to the user
    """
    # Create or get verification token
    token, created = EmailVerificationToken.objects.get_or_create(
        user=user,
        defaults={
            'expires_at': timezone.now() + timezone.timedelta(hours=24)
        }
    )

    # If token exists but expired, refresh it
    if not created and not token.is_valid():
        token.verified = False
        token.token = token._meta.get_field('token').default()
        token.expires_at = timezone.now() + timezone.timedelta(hours=24)
        token.save()

    verification_url = f"{settings.SITE_URL}/api/auth/verify-email/{token.token}/"

    # Send email
    send_mail(
        subject='Verify your email address',
        message=f'Hello {user.username},\n\n'
               f'Please verify your email address by clicking on the link below:\n\n'
               f'{verification_url}\n\n'
               f'This link will expire in 24 hours.\n\n'
               f'If you did not create an account, please ignore this email.\n\n'
               f'Thanks,\nThe Auth API Team',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )

    return token

def send_password_reset_email(user):
    """
    Create a password reset token and send password reset email to the user
    """
    # Invalidate any existing tokens for this user
    PasswordResetToken.objects.filter(user=user, used=False).update(used=True)

    # Create new token
    token = PasswordResetToken.objects.create(
        user=user,
        expires_at=timezone.now() + timezone.timedelta(hours=1)
    )

    reset_url = f"{settings.SITE_URL}/api/auth/reset-password/{token.token}/"

    # Send email
    send_mail(
        subject='Reset your password',
        message=f'Hello {user.username},\n\n'
               f'You requested to reset your password. Please click on the link below:\n\n'
               f'{reset_url}\n\n'
               f'This link will expire in 1 hour.\n\n'
               f'If you did not request a password reset, please ignore this email.\n\n'
               f'Thanks,\nThe Auth API Team',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )

    return token
