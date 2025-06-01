from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid

def generate_key():
    """Generate a random API key"""
    return uuid.uuid4().hex

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
