# Multi-Tenant Authentication Service

A production-ready authentication and authorization service built with Spring Boot, designed for SaaS applications requiring secure multi-tenant authentication.

The service supports local authentication, OAuth2 login, JWT authentication, refresh token rotation, role-based access control, email verification, password reset, and tenant-aware authorization.

![Java](https://img.shields.io/badge/Java-17-blue)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.0.7-brightgreen)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-blue)
![Redis](https://img.shields.io/badge/Redis-Cloud-red)

Live API:- [mtAuth Swagger](https://mtauth.onrender.com/swagger-ui/index.html)

---


## Features

- Multi-Tenant Authentication
- JWT Access & Refresh Tokens
- Refresh Token Rotation
- Redis-backed Token Management
- JWT Blacklisting using Redis Pub/Sub
- OAuth2 Login (Google, GitHub, etc.)
- Email Verification
- Password Reset
- Role-Based Access Control (RBAC)
- Client Registration
- Tenant Isolation
- Stateless Authentication
- Local Signup Email Verification

---

## Tech Stack

| Technology | Version                 |
|------------|-------------------------|
| Java | 17                      |
| Spring Boot | 4.0.7                   |
| Spring Security | 7                       |
| PostgreSQL | Local (Development)     |
| Neon PostgreSQL | Production              |
| Redis | Local (Development)     |
| Redis Cloud | Production              |
| Maven | 3.9.x                   |
| OAuth2 | Authorization Code Flow |
| JWT | Access & Refresh Tokens |

---

## Architecture

```
                  +----------------+
                  |    Frontend    |
                  +-------+--------+
                          |
                          |
                JWT / OAuth Requests
                          |
                          ▼
           +----------------------------+
           | Multi-Tenant Auth Service  |
           +----------------------------+
              |                  |
              |                  |
              ▼                  ▼
      PostgreSQL            Redis
    (Users, Roles,       Refresh Tokens,
      Clients...)        Blacklist, OAuth
```

---

## Security Features

- JWT Authentication
- Refresh Token Rotation
- Redis-backed Refresh Tokens
- JWT Blacklisting
- Redis Pub/Sub Synchronization
- OAuth Authorization Code Exchange
- Email Verification
- Password Reset Tokens
- Client Secret Validation
- Tenant Isolation
- Role-Based Authorization

---

## Supported Authentication Flows

### Local Authentication

```
Signup
    ↓
Verify Email
    ↓
Login
    ↓
Access Token + Refresh Token
    ↓
Refresh Token Rotation
    ↓
Logout
```

---

### OAuth Authentication

```
Frontend
    ↓
/oauth/{provider}/start
    ↓
OAuth Provider
    ↓
/oauth/{provider}/callback
    ↓
Temporary Exchange Code
    ↓
/oauth/exchange
    ↓
Access Token + Refresh Token
```

---

## Getting Started

### Prerequisites

- Java 17
- Maven
- PostgreSQL
- Redis

---

### Clone Repository

```bash
git clone https://github.com/harsh25519/mtAuth.git

cd <repository where you clone repo>
```

---

### Configure Environment

Create an `application-dev.properties` (or use environment variables) and configure:

- PostgreSQL
- Redis
- SMTP Mail
- JWT Secret
- OAuth Client Credentials

---

### Run the Application

```bash
./mvnw spring-boot:run
```

or

```bash
mvn spring-boot:run
```

The application starts on

```
http://localhost:8080
```

---

## Swagger UI

Once the application is running:

```
http://localhost:8080/swagger-ui.html
```

---

## API Documentation

Detailed documentation is available in the **docs** folder.

- Authentication APIs
- OAuth APIs
- User APIs
- Client APIs
- Security
- Error Responses

---

## Project Structure

```
docs/
├── authentication.md
├── oauth.md
├── users.md
├── clients.md
├── security.md
└── getting-started.md
```

---

## Roles

| Role | Description |
|------|-------------|
| AUTH_ADMIN | Global administrator |
| ADMIN | Tenant administrator |
| USER | Standard authenticated user |

---

## Token Lifetime

| Token | Lifetime |
|--------|----------|
| Access Token | 15 Minutes |
| Refresh Token | 7 Days |
| OAuth Exchange Code | 30–60 Seconds |

---

## Production Services

| Service | Development | Production |
|---------|-------------|------------|
| PostgreSQL | Local PostgreSQL | Neon PostgreSQL |
| Redis | Local Redis | Redis Cloud |

---


## License

This project is licensed under the MIT License.
