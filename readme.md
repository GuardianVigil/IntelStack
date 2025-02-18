# GuardianVigil - Threat Intelligence Platform

GuardianVigil is a comprehensive threat intelligence platform that integrates with multiple security services to provide real-time threat analysis, monitoring, and reporting capabilities.

## 🚀 Features

- **Multi-Platform Integration**: Connect with various security services including:
  - VirusTotal
  - CrowdSec
  - GreyNoise
  - AbuseIPDB
  - Hybrid Analysis
  - AlienVault OTX
  - URLScan.io
  - SecurityTrails
  - And many more...

- **Secure API Key Management**:
  - Encrypted storage of API keys
  - Masked display for security
  - Easy testing of API key validity
  - Per-user API key management

- **Threat Analysis Tools**:
  - IP Analysis
  - Hash Analysis
  - Domain Reputation
  - URL Scanning
  - Email Investigation

- **Modern UI/UX**:
  - Responsive design
  - Dark/Light mode support
  - Interactive dashboards
  - Real-time notifications

## 🛠️ Technology Stack

- **Backend**: Django 4.2+
- **Frontend**: TailwindCSS
- **Database**: PostgreSQL (recommended)
- **Caching**: Redis
- **Security**: Cryptography for API key encryption
- **Async Support**: aiohttp, asyncio

## 📋 Prerequisites

- Python 3.8+
- Redis Server
- PostgreSQL (recommended)
- Node.js and npm (for TailwindCSS)

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/GuardianVigil.git
cd GuardianVigil
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Run migrations:
```bash
python manage.py migrate
```

6. Create a superuser:
```bash
python manage.py createsuperuser
```

7. Start the development server:
```bash
python manage.py runserver
```

## 🔐 Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
DEBUG=True
SECRET_KEY=your-secret-key
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
REDIS_URL=redis://localhost:6379/0
ENCRYPTION_KEY=your-encryption-key
```

## 🚦 API Configuration

1. Navigate to the API Configuration page
2. Add your API keys for the services you want to use
3. Use the "Test" button to verify API key validity
4. API keys are automatically encrypted before storage

## 🔒 Security Features

- API keys are encrypted using Fernet (symmetric encryption)
- All sensitive data is encrypted at rest
- API key display is masked for security
- CSRF protection enabled
- Rate limiting on sensitive endpoints

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Django](https://www.djangoproject.com/)
- [TailwindCSS](https://tailwindcss.com/)
- All the integrated security service providers

## 📞 Support

For support, email support@guardianvigil.com or open an issue in the repository.