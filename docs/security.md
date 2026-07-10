# Security

This document describes the security mechanisms implemented by the Multi-Tenant Authentication Service.

---

# Authentication

The service uses stateless JWT authentication.

After successful authentication, the client receives:

- Access Token
- Refresh Token

The access token is included in every protected request.

```http
Authorization: Bearer <access_token>
```

---

# Access Token

- Signed JWT
- Lifetime: 15 minutes
- Contains:
    - userId
    - clientId
    - roles
    - jti (JWT ID)

Access tokens are never stored in the database.

---

# Refresh Token

Refresh tokens are stored in Redis.

Features:

- 7 day lifetime
- Token rotation
- Old refresh tokens become invalid
- Fast lookup using Redis

---

# Refresh Token Rotation

Every successful refresh request generates:

- New Access Token
- New Refresh Token

The previous refresh token is immediately invalidated.

This prevents replay attacks using stolen refresh tokens.

---

# Logout

Logout invalidates the current access token.

The service:

1. Extracts the JWT JTI.
2. Stores the JTI in Redis blacklist.
3. Publishes the blacklist event using Redis Pub/Sub.

Every service instance receives the blacklist event and rejects the revoked token.

---

# Redis

Redis is used for:

- Refresh Tokens
- Blacklisted JWT IDs
- OAuth Exchange Codes

Redis is not used as a session store.

Authentication remains stateless.

---

# Multi-Tenant Isolation

Every authenticated JWT contains a clientId.

Protected operations validate tenant ownership in the service layer before accessing resources.

This prevents users from accessing data belonging to another tenant.

---

# Role-Based Access Control

Authorization is based on user roles.

Current roles include:

| Role | Description |
|------|-------------|
| AUTH_ADMIN | Global administrator |
| ADMIN | Tenant administrator |
| USER | Standard authenticated user |

Protected endpoints verify required roles before executing business logic.

---

# OAuth Security

OAuth login uses the Authorization Code flow.

Instead of returning JWTs directly after OAuth authentication:

1. OAuth Provider authenticates the user.
2. Authentication Service creates a temporary exchange code.
3. The user is redirected to the registered client.
4. The client exchanges the temporary code for JWT tokens.

Exchange codes:

- Short lived (30–60 seconds)
- Single use
- Stored in Redis

This prevents JWTs from being exposed in browser URLs.

---

# Email Verification

New local accounts require email verification.

Verification links contain secure random tokens.

After successful verification:

- Token is deleted
- User account becomes active

---

# Password Reset

Password reset uses secure one-time tokens.

Reset tokens:

- Expire automatically
- Can only be used once
- Are deleted after successful password reset

---

# Password Storage

User passwords are never stored in plain text.

Passwords are hashed using BCrypt before being persisted.

---

# Client Authentication

Every tenant application receives:

- clientId
- clientSecret

Sensitive operations validate client credentials before issuing tokens.

The client secret is displayed only once during client registration.

---

## Event-Driven Token Revocation

JWT authentication is stateless; however, access tokens can be explicitly revoked during logout.

When a user logs out:

1. The JWT's `jti` (JWT ID) is added to a Redis blacklist.
2. A blacklist event is published using Redis Pub/Sub.
3. Subscriber services update their local blacklist cache and reject revoked tokens.

This mechanism enables distributed token revocation across multiple services without introducing server-side sessions.

> **Current implementation:** Redis Pub/Sub  
> **Future improvement:** Kafka or another dedicated event streaming platform for improved scalability and reliability.

---

# Security Summary

Implemented security features:

- JWT Authentication
- Refresh Token Rotation
- Redis-backed Token Storage
- JWT Blacklisting
- Redis Pub/Sub
- OAuth Authorization Code Flow
- Email Verification
- Password Reset
- BCrypt Password Hashing
- Multi-Tenant Isolation
- Role-Based Authorization