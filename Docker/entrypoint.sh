#!/bin/sh

# Exit on error
set -e

# Create necessary directories
mkdir -p /app/storage

# Create database file if it doesn't exist
touch /app/db.sqlite3
chmod 777 /app/db.sqlite3

# Start Redis server
redis-server /etc/redis.conf &
sleep 2

# Wait for the database to be ready
echo "Waiting for database..."
sleep 3

# Apply database migrations
echo "Applying database migrations..."
/app/venv/bin/python /app/manage.py migrate --noinput

# Create superuser if environment variables are set
if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ]; then
    echo "Creating superuser..."
    /app/venv/bin/python /app/manage.py createsuperuser --noinput || echo "Superuser already exists."
fi

# Start supervisor to manage Redis and Django
echo "Starting services with supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf