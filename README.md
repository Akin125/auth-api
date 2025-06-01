# 🔐 Auth API - Comprehensive Authentication System

[![Django](https://img.shields.io/badge/Django-5.2.1-green.svg)](https://www.djangoproject.com/)
[![DRF](https://img.shields.io/badge/DRF-3.16.0-red.svg)](https://www.django-rest-framework.org/)
[![JWT](https://img.shields.io/badge/JWT-Authentication-blue.svg)](https://django-rest-framework-simplejwt.readthedocs.io/)
[![API Documentation](https://img.shields.io/badge/API-Documentation-orange.svg)](https://swagger.io/)

A robust Django-based authentication API that provides secure user management, authentication, and authorization services through RESTful endpoints.

## ✨ Features

- **🔑 API Key Authentication**: Secure API endpoints with unique API keys
- **👤 User Registration & Management**: Create and manage user accounts
- **🔒 JWT Authentication**: Secure token-based authentication system
- **✉️ Email Verification**: Verify user emails via tokens
- **🔄 Password Reset**: Secure password reset workflow
- **👁️ User Profile Management**: View and update user profiles
- **📚 Interactive API Documentation**: Swagger and ReDoc UI for easy API exploration

## 🛠️ Technology Stack

- **Django 5.2.1**: High-level Python web framework
- **Django REST Framework 3.16.0**: Toolkit for building Web APIs
- **Simple JWT 5.5.0**: JSON Web Token authentication for DRF
- **drf-yasg 1.21.10**: Yet Another Swagger Generator
- **PostgreSQL**: Database (configurable for development/production)
- **CORS Headers**: Cross-Origin Resource Sharing support

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip package manager
- PostgreSQL (for production)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/auth-api.git
   cd auth-api
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file in the project root with:
   ```
   SECRET_KEY=your_secret_key
   DEBUG=True
   DATABASE_URL=sqlite:///db.sqlite3
   SITE_URL=http://localhost:8000
   DEFAULT_FROM_EMAIL=youremail@example.com
   ```

5. **Run migrations**
   ```bash
   python manage.py migrate
   ```

6. **Create a superuser**
   ```bash
   python manage.py createsuperuser
   ```

7. **Run the development server**
   ```bash
   python manage.py runserver
   ```

## 📋 API Endpoints

### Authentication Endpoints

| Endpoint                     | Method | Description                         | Authentication |
|------------------------------|--------|-------------------------------------|---------------|
| `/api/auth/register/`        | POST   | Register a new user                 | API Key       |
| `/api/auth/login/`           | POST   | Login and get JWT tokens            | API Key       |
| `/api/auth/profile/`         | GET    | Get user profile                    | JWT Token     |
| `/api/auth/verify-email/`    | POST   | Verify email with token             | None          |
| `/api/auth/verify-email/<token>/` | GET | Verify email via link              | None          |
| `/api/auth/request-password-reset/` | POST | Request password reset           | None          |
| `/api/auth/reset-password/`  | POST   | Reset password with token           | None          |
| `/api/auth/reset-password/<token>/` | GET | Password reset via link           | None          |

### Documentation Endpoints

| Endpoint        | Description                                  |
|-----------------|----------------------------------------------|
| `/api/docs/swagger/` | Interactive Swagger documentation UI         |
| `/api/docs/redoc/`   | ReDoc documentation UI (user-friendly)      |

## 🔐 Authentication Flow

### Registration Flow
1. Client sends registration data to `/api/auth/register/` with a valid API key
2. Server creates an inactive user account
3. Verification email is sent to the user's email address
4. User verifies email by clicking the link or using the token
5. User account is activated and can be used for login

### Login Flow
1. Client sends login credentials to `/api/auth/login/` with a valid API key
2. Server validates credentials and returns JWT tokens (access and refresh)
3. Client uses the access token for subsequent authenticated requests

### Password Reset Flow
1. User requests password reset at `/api/auth/request-password-reset/`
2. Server sends a password reset email with token/link
3. User submits new password with token to `/api/auth/reset-password/`
4. Password is updated if token is valid

## 📝 API Key Management

API keys are required for registration and login endpoints to prevent abuse. To generate an API key:

1. Access Django admin at `/admin/`
2. Navigate to APIKey model
3. Create a new API key with appropriate service name and description
4. Use the generated key in requests via the `X-API-Key` header

## 🌐 Environment Variables

| Variable Name        | Description                               | Default Value              |
|---------------------|-------------------------------------------|----------------------------|
| SECRET_KEY          | Django secret key                         | (required)                 |
| DEBUG               | Debug mode flag                           | False                      |
| DATABASE_URL        | Database connection URL                   | sqlite:///db.sqlite3       |
| SITE_URL            | Base URL for generating links in emails   | http://localhost:8000      |
| EMAIL_HOST          | SMTP server host                          | None (uses console if not set)|
| EMAIL_PORT          | SMTP server port                          | 587                        |
| EMAIL_USE_TLS       | Use TLS for email                         | True                       |
| EMAIL_HOST_USER     | SMTP username                             | ""                         |
| EMAIL_HOST_PASSWORD | SMTP password                             | ""                         |
| DEFAULT_FROM_EMAIL  | Default sender email                      | philipoluseyi@gmail.com    |

## 📦 Deployment

The project is configured for easy deployment to various platforms:

### Heroku
```bash
heroku create
git push heroku main
heroku run python manage.py migrate
heroku run python manage.py createsuperuser
```

### Docker
A Dockerfile and docker-compose.yml are provided for containerized deployment.

## 📚 Documentation

Comprehensive API documentation is available at:
- Swagger UI: `/api/docs/swagger/`
- ReDoc UI: `/api/docs/redoc/`

## 🧪 Testing

Run tests with:
```bash
python manage.py test
```

## 🔄 JWT Settings

- Access Token Lifetime: 60 minutes
- Refresh Token Lifetime: 1 day

## 👨‍💻 Author

- **Seyifunmi Philip** - [philipoluseyi@gmail.com](mailto:philipoluseyi@gmail.com)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

