# Base image: Alpine Linux
FROM alpine:3.19

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    py3-virtualenv \
    redis \
    build-base \
    python3-dev \
    libffi-dev \
    openssl-dev \
    curl \
    supervisor \
    tzdata

# Set timezone data
ENV TZ=UTC
RUN cp /usr/share/zoneinfo/UTC /etc/localtime

# Set Python to use UTF-8 encoding
ENV PYTHONIOENCODING=utf-8
ENV PYTHONUNBUFFERED=1
ENV LANG=C.UTF-8
ENV DJANGO_SETTINGS_MODULE=vristo.settings
ENV PATH="/app/venv/bin:$PATH"

# Copy requirements.txt first for better caching
COPY requirements.txt /app/

# Create necessary directories
RUN mkdir -p /app/storage/screenshots /app/staticfiles

# Create and activate virtual environment
RUN python3 -m venv /app/venv

# Install Python dependencies
RUN /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy configuration files first
COPY Docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY Docker/redis.conf /etc/redis.conf

# Copy the project files
COPY . /app/

# Copy and make entrypoint script executable (do this LAST)
COPY Docker/entrypoint.sh /app/entrypoint.sh
# Fix line endings and make executable
RUN sed -i 's/\r$//' /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Create an encryption key if it doesn't exist
RUN if [ ! -f /app/encryption.key ]; then \
    /app/venv/bin/python -c "from cryptography.fernet import Fernet; key = Fernet.generate_key(); open('/app/encryption.key', 'wb').write(key)" \
    && chmod 600 /app/encryption.key; \
    fi

# Expose the application port
EXPOSE 8000

# Start supervisor which will manage Redis and the Django app
ENTRYPOINT ["/app/entrypoint.sh"]