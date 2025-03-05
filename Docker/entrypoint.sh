#!/bin/sh

# Exit on error
set -e

# Wait for the database to be ready
echo "Waiting for database..."
sleep 5

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate --noinput

# Create superuser if environment variables are set
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ]; then
    echo "Creating superuser..."
    python manage.py createsuperuser --noinput || echo "Superuser already exists."
fi

# Start supervisor to manage Redis and Django
echo "Starting services with supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
