from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
from django.utils.crypto import get_random_string

def generate_key():
    """Generate a random API key"""
    return uuid.uuid4().hex

def generate_verification_token():
    """Generate a random verification token"""
    return get_random_string(64)

def generate_reset_token():
    """Generate a random password reset token"""
    return get_random_string(64)

class APIKey(models.Model):
    key = models.CharField(max_length=40, unique=True, default=generate_key)
    name = models.CharField(max_length=50)
    description = models.TextField(blank=True)
    service = models.CharField(max_length=100, help_text="Service or feature this key is for")
    created = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys', null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.service})"

    def is_valid(self):
        """Check if the API key is valid (active and not expired)"""
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < timezone.now():
            return False
        return True

    def refresh(self):
        """Generate a new key value for this API key"""
        self.key = generate_key()
        self.save()

class EmailVerificationToken(models.Model):
    """Model for storing email verification tokens"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='verification_token')
    token = models.CharField(max_length=64, unique=True, default=generate_verification_token)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Verification token for {self.user.username}"

    def save(self, *args, **kwargs):
        # Set expiration to 24 hours from creation if not set
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if the token is valid (not expired and not used)"""
        return not self.verified and self.expires_at > timezone.now()

class PasswordResetToken(models.Model):
    """Model for storing password reset tokens"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=64, unique=True, default=generate_reset_token)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def __str__(self):
        return f"Password reset token for {self.user.username}"

    def save(self, *args, **kwargs):
        # Set expiration to 1 hour from creation if not set
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=1)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if the token is valid (not expired and not used)"""
        return not self.used and self.expires_at > timezone.now()

