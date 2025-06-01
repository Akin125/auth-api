#!/bin/bash

# Install dependencies
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput

# Run migrations
python manage.py migrate

# Create superuser if needed (only if environment variables are set)
if [[ -n "$DJANGO_SUPERUSER_USERNAME" ]] && [[ -n "$DJANGO_SUPERUSER_PASSWORD" ]] && [[ -n "$DJANGO_SUPERUSER_EMAIL" ]]; then
    python manage.py createsuperuser --noinput
fi

