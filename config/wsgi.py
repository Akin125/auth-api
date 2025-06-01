"""
WSGI config for config project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

import os
import django

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Setup Django
django.setup()

# Run migrations automatically on startup
from django.core.management import call_command
try:
    call_command('migrate', interactive=False)
except Exception as e:
    # Optionally log this or print it
    print(f"Migration error: {e}")

# Create superuser if it doesn't exist
from django.contrib.auth.models import User

ADMIN_USERNAME = os.getenv('DJANGO_SUPERUSER_USERNAME', 'admin')
ADMIN_EMAIL = os.getenv('DJANGO_SUPERUSER_EMAIL', 'admin@example.com')
ADMIN_PASSWORD = os.getenv('DJANGO_SUPERUSER_PASSWORD', 'adminpassword')

if not User.objects.filter(username=ADMIN_USERNAME).exists():
    User.objects.create_superuser(
        username=ADMIN_USERNAME,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD
    )

application = get_wsgi_application()
