#!/bin/bash

# Install dependencies
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput

# Run migrations
python manage.py migrate
# Check if the database is ready
while ! python manage.py check --database default; do
    echo "Waiting for the database to be ready..."
    sleep 2
done


# Create superuser if needed (only if environment variables are set)
if [[ -n "$DJANGO_SUPERUSER_USERNAME" ]] && [[ -n "$DJANGO_SUPERUSER_PASSWORD" ]] && [[ -n "$DJANGO_SUPERUSER_EMAIL" ]]; then
    # Check if the superuser already exists
    echo "from django.contrib.auth import get_user_model; User = get_user_model(); print(User.objects.filter(username='$DJANGO_SUPERUSER_USERNAME').exists())" | python manage.py shell > /tmp/user_exists.txt
    USER_EXISTS=$(cat /tmp/user_exists.txt)

    if [[ $USER_EXISTS == "False" ]]; then
        python manage.py createsuperuser --noinput
        echo "Superuser '$DJANGO_SUPERUSER_USERNAME' created successfully."
    else
        echo "Superuser '$DJANGO_SUPERUSER_USERNAME' already exists."
    fi
fi


