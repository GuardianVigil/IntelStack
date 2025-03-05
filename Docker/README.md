# IntelStack Docker Setup

This directory contains all the necessary files to run IntelStack in a Docker container.

## Files Overview

- `Dockerfile`: Builds the IntelStack container using Alpine Linux
- `docker-compose.yml`: Defines the service configuration
- `entrypoint.sh`: Script that runs when the container starts
- `supervisord.conf`: Configuration for supervisor to manage Redis and Django
- `redis.conf`: Configuration for Redis server

## Quick Start

1. From the project root directory, run:
   ```
   docker-compose -f Docker/docker-compose.yml up -d
   ```

2. Access the application at http://localhost:8000

## Environment Variables

You can customize the following environment variables:

- `DJANGO_SUPERUSER_USERNAME`: Admin username (default: admin)
- `DJANGO_SUPERUSER_EMAIL`: Admin email (default: admin@example.com)
- `DJANGO_SUPERUSER_PASSWORD`: Admin password (default: admin123)
- `SECRET_KEY`: Django secret key
- `DEBUG`: Set to True for development mode

Example:
```
DJANGO_SUPERUSER_USERNAME=myadmin DJANGO_SUPERUSER_PASSWORD=mysecurepassword docker-compose -f Docker/docker-compose.yml up -d
```

## Data Persistence

The following data is persisted through Docker volumes:

- Database: `db.sqlite3`
- Storage: `storage/` directory
- Static files: `staticfiles/` directory

## Publishing to Docker Hub

To publish this image to Docker Hub:

1. Build the image:
   ```
   docker build -t yourusername/intelstack:latest -f Docker/Dockerfile .
   ```

2. Push to Docker Hub:
   ```
   docker push yourusername/intelstack:latest
   ```
