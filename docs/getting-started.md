# Multi-Tenant Authentication Service — API Documentation

**Version:** 1.0

**Base URL:** `https://mtAuth.onrender.com` 

**Protocol:** REST over HTTPS

**Auth scheme:** `Bearer <JWT>`

A production-ready multi-tenant authentication and authorization service supporting local (email/password) login, OAuth2 (Google, GitHub, etc.), JWT access/refresh tokens, Redis-backed session revocation, email verification, and password reset.

---

## Getting Started

Before using this API, every tenant must register a client application.

After registration the client receives:

- clientId
- clientSecret
- redirectUrl

These credentials are required when calling authentication and OAuth endpoints.

---

## Conventions

- All request/response bodies are `application/json` unless noted.
- All timestamps are ISO-8601 / RFC 3339 with UTC offset (e.g. `2026-07-08T10:00:00Z`).
- All identifiers (`userId`, `clientId`) are UUID v4.
- Every tenant-scoped request requires a `clientId` — either in the body or resolved from the authenticated token.
- Endpoints marked **Public** require no `Authorization` header. Endpoints marked **Authenticated** require a valid, non-blacklisted access token.
- Endpoints that return lists are **paginated**. Query params: `page` (0-indexed, default `0`), `size` (default `20`). Response shape:

```json
{
  "content": [ ],
  "page": 0,
  "size": 20,
  "totalElements": 134,
  "totalPages": 7
}
```

---

## Authentication & Headers

| Header | Required On | Example |
|---|---|---|
| `Content-Type` | All `POST`/`PUT` requests | `application/json` |
| `Authorization` | All **Authenticated** endpoints | `Authorization: Bearer eyJhbGciOi...` |

If `Authorization` is missing, malformed, expired, or the token's `jti` is blacklisted, every **Authenticated** endpoint returns `401 Unauthorized` with the standard error body (below) — this is not repeated per-endpoint.

---

## Error Format

All error responses share a single shape:

```json
{
  "timestamp": "2026-07-08T10:00:00Z",
  "status": 400,
  "error": "VALIDATION_ERROR",
  "message": "email must be a valid email address",
  "path": "/auth/signup"
}
```

### Standard status codes used across this API

| Status | Meaning | Typical Cause |
|---|---|---|
| `200 OK` | Success | Standard successful response |
| `204 No Content` | Success, no body | Logout |
| `400 Bad Request` | Validation error | Malformed email, weak password, missing field |
| `401 Unauthorized` | Auth failure | Missing/expired/blacklisted token, bad credentials |
| `403 Forbidden` | Authz failure | Valid token, insufficient role, or wrong tenant (`clientId` mismatch) |
| `404 Not Found` | Resource missing | Unknown user, invalid/expired verification or reset token |
| `409 Conflict` | Duplicate resource | Email already registered under this `clientId` |
| `500 Internal Server Error` | Unexpected failure | Unhandled exception |

Per-endpoint tables below only call out the errors that are *specific* or *most likely* for that endpoint — assume `400` and `500` are always possible.

---

## Response Objects

### `MessageResponse`

```json
{
  "message": "Operation completed successfully."
}
```

### `AuthResponse`

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "8f14e45f-ceea-4c3c-b8f0-9a62d2246421",
  "tokenType": "Bearer"
}
```

### `UserResponse`

```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "email": "john@example.com",
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000",
  "isActive": true,
  "authProvider": "LOCAL",
  "roles": ["ROLE_USER"],
  "createdAt": "2026-07-08T10:00:00Z"
}
```

### `JwtPrincipal` (server-side security context — not returned over the wire)

```java
JwtPrincipal(
    UUID userId,
    UUID clientId,
    List<String> roles
);
```

### `ErrorResponse`

```json
{
  "timestamp": "2026-07-08T10:00:00Z",
  "status": 400,
  "message": "string describing what went wrong"
}
```

---