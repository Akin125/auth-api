from rest_framework import authentication
from rest_framework import exceptions
from .models import APIKey

class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication using X-API-Key header
    """
    def authenticate(self, request):
        api_key = request.META.get('HTTP_X_API_KEY')
        if not api_key:
            return None  # No API key provided

        try:
            key = APIKey.objects.get(key=api_key, is_active=True)
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid or inactive API key')

        return (None, key)
