# Development Setup Guide

This guide will help you set up your development environment for Stack.

## Prerequisites

- Python 3.8 or higher
- PostgreSQL 12 or higher
- Redis 6 or higher
- Node.js 14 or higher
- Git

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/GuardianVigil/Stack.git
cd Stack
```

### 2. Set Up Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Database Setup

```bash
# Create PostgreSQL database
createdb stack_db

# Run migrations
python manage.py migrate
```

### 4. Environment Configuration

Create a `.env` file in the project root:

```env
DEBUG=True
SECRET_KEY=your-secret-key
DATABASE_URL=postgres://localhost/stack_db
REDIS_URL=redis://localhost:6379/0

# API Keys for Threat Intelligence Services
VIRUSTOTAL_API_KEY=your-virustotal-key
GREYNOISE_API_KEY=your-greynoise-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
# Add other API keys as needed
```

### 5. Start Development Server

```bash
# Start Redis server
redis-server

# Start Celery worker
celery -A stack worker -l info

# Run development server
python manage.py runserver
```

The application will be available at `http://localhost:8000`

## Development Tools

### Code Quality Tools

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run linter
flake8

# Run type checker
mypy .

# Run tests
pytest
```

### Frontend Development

```bash
# Install Node.js dependencies
npm install

# Run frontend development server
npm run dev

# Build frontend assets
npm run build
```

## Docker Development Environment

Alternatively, you can use Docker for development:

```bash
# Build and start containers
docker-compose up -d

# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser
```

## IDE Setup

### VSCode Configuration

Create `.vscode/settings.json`:

```json
{
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

### PyCharm Configuration

- Set Python interpreter to the virtual environment
- Enable Django support
- Configure test runner to use pytest

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_analysis.py

# Run with coverage report
pytest --cov=stack
```

### Creating Test Data

```bash
# Load initial test data
python manage.py loaddata initial_data.json

# Create test user
python manage.py create_test_user
```

## Common Issues

### Database Connection Issues
- Ensure PostgreSQL is running
- Check database credentials in `.env`
- Verify database permissions

### Redis Connection Issues
- Ensure Redis server is running
- Check Redis connection URL
- Verify Redis port is not blocked

### API Integration Issues
- Verify API keys in `.env`
- Check API rate limits
- Ensure network connectivity

## Additional Resources

- [Django Documentation](https://docs.djangoproject.com/)
- [Celery Documentation](https://docs.celeryproject.org/)
- [TailwindCSS Documentation](https://tailwindcss.com/docs)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
