# Installation Guide

## System Requirements

### Hardware Requirements
- CPU: 4+ cores recommended
- RAM: 8GB minimum, 16GB recommended
- Storage: 20GB minimum free space
- Network: Stable internet connection

### Software Requirements
- Python 3.8 or higher
- Node.js 14.x or higher
- Redis 6.x or higher
- PostgreSQL 12.x or higher
- Git

## Installation Steps

### 1. Clone the Repository
```bash
git clone https://github.com/GuardianVigil/IntelStack.git
cd IntelStack
```

### 2. Set Up Python Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Install Node.js Dependencies
```bash
# Install frontend dependencies
cd frontend
npm install
```

### 4. Database Setup
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib

# Create database
sudo -u postgres psql
postgres=# CREATE DATABASE intelstack;
postgres=# CREATE USER intelstack WITH PASSWORD 'your_password';
postgres=# GRANT ALL PRIVILEGES ON DATABASE intelstack TO intelstack;
```

### 5. Redis Setup
```bash
# Install Redis (Ubuntu/Debian)
sudo apt-get install redis-server

# Start Redis service
sudo systemctl start redis
sudo systemctl enable redis
```

### 6. Environment Configuration
```bash
# Copy example environment file
cp .env.example .env

# Edit .env file with your configuration
nano .env
```

Required environment variables:
```env
# Database Configuration
DB_NAME=intelstack
DB_USER=intelstack
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Platform API Keys
VIRUSTOTAL_API_KEY=your_key
HYBRID_ANALYSIS_API_KEY=your_key
MALWAREBAZAAR_API_KEY=your_key
THREATFOX_API_KEY=your_key
FILESCAN_API_KEY=your_key
METADEFENDER_API_KEY=your_key

# Application Settings
DEBUG=False
SECRET_KEY=your_secret_key
ALLOWED_HOSTS=localhost,127.0.0.1
```

### 7. Initialize Database
```bash
# Apply database migrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser
```

### 8. Build Frontend Assets
```bash
# Build frontend
cd frontend
npm run build
```

### 9. Start Services
```bash
# Start Redis (if not already running)
sudo systemctl start redis

# Start PostgreSQL (if not already running)
sudo systemctl start postgresql

# Start Celery worker
celery -A intelstack worker -l info

# Start development server
python manage.py runserver
```

## Docker Installation

### Using Docker Compose
```bash
# Build and start containers
docker-compose up -d

# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser
```

## Verification

### 1. Check Services
```bash
# Check PostgreSQL
psql -U intelstack -d intelstack -c "\l"

# Check Redis
redis-cli ping

# Check web server
curl http://localhost:8000/health
```

### 2. Test Platform Connections
```bash
# Run platform connection tests
python manage.py test platforms.tests.test_connections
```

## Troubleshooting

### Common Issues

1. **Database Connection Issues**
```bash
# Check PostgreSQL service
sudo systemctl status postgresql

# Check database logs
sudo tail -f /var/log/postgresql/postgresql-12-main.log
```

2. **Redis Connection Issues**
```bash
# Check Redis service
sudo systemctl status redis

# Check Redis logs
sudo tail -f /var/log/redis/redis-server.log
```

3. **Permission Issues**
```bash
# Fix file permissions
sudo chown -R $USER:$USER .
chmod -R 755 .
```

### Getting Help
- Submit issues on GitHub
- Check the troubleshooting guide
- Join our Discord community

## Security Notes

1. **API Key Security**
- Store API keys securely in environment variables
- Never commit API keys to version control
- Regularly rotate API keys

2. **Database Security**
- Use strong passwords
- Limit database access to localhost
- Regular security updates

3. **Application Security**
- Enable HTTPS in production
- Set secure cookie settings
- Configure CORS properly

## Next Steps

After installation:
1. Configure platform API keys
2. Set up monitoring
3. Configure backup system
4. Review security settings
