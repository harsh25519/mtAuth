## Auth API (`/auth`)

## Workflows

### Local Authentication Lifecycle

```
 ┌──────────┐     ┌─────────────────┐     ┌──────────────┐       ┌───────┐
 │  Signup  │────▶│ Verification    │────▶│ Verify Email │────▶│ Login │
 │          │     │ Email Sent      │     │              │       │       │
 └──────────┘     └─────────────────┘     └──────────────┘       └───┬───┘
                                                                    │
                                                                    ▼
                                                     ┌─────────────────────────┐
                                                     │ Access Token (15 min)   │
                                                     │ Refresh Token (7 days)  │
                                                     └────────────┬────────────┘
                                                                  │
                                        ┌─────────────────────────┼───────────────────────┐
                                        ▼                                                  ▼
                          ┌────────────────────────┐                             ┌──────────────┐
                          │ Refresh Token Rotation │                             │    Logout    │
                          │ (repeat as needed)     │                             │ (blacklist)  │
                          └────────────────────────┘                             └──────────────┘
```

### Password Reset Flow

```
 ┌──────────────────┐     ┌────────────────────┐      ┌────────────────┐
 │ Forgot Password  │────▶│ Reset Email Sent   │────▶│ Reset Password │
 │ POST /forgot-pw  │     │ (token in link)    │      │ POST /reset-pw │
 └──────────────────┘     └────────────────────┘      └────────────────┘
```

### Logout / Revocation Flow

```
 ┌────────┐     ┌───────────────────┐      ┌────────────────────┐     ┌─────────────────────────┐
 │ Client │────▶│ POST /auth/logout │────▶│ Extract JTI from   │───▶│ Blacklist JTI in Redis  │
 │        │     │ (Bearer token)    │      │ access token       │     │                         │
 └────────┘     └───────────────────┘      └────────────────────┘     └──────────┬──────────────┘
                                                                                 ▼
                                                                  ┌──────────────────────────────┐
                                                                  │ Publish blacklist event via  │
                                                                  │ Redis Pub/Sub → all tenant   │
                                                                  │ services invalidate locally  │
                                                                  └──────────────────────────────┘
```


### 1. Signup

`POST /auth/signup`
**Access:** Public

Creates a new user under a tenant. The account starts unverified (`verified = false`) and a verification email is dispatched.

**Request body — `LocalSignupRequest`**

```json
{
  "email": "john@example.com",
  "password": "Password@123",
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000",
  "clientSecret": "tenant-secret"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `email` | string | yes | Must be a valid email; unique per `clientId` |
| `password` | string | yes | Minimum 8 chars, recommend upper/lower/digit/symbol |
| `clientId` | UUID | yes | Identifies the tenant |
| `clientSecret` | string | yes | Validates the calling client is registered |

**Success — `200 OK`**

```json
{ "message": "Verification email sent." }
```

**Errors**

| Status | Error | Cause |
|---|---|---|
| `400` | `VALIDATION_ERROR` | Invalid email/password format |
| `401` | `INVALID_CLIENT_CREDENTIALS` | Bad `clientId`/`clientSecret` pair |
| `409` | `EMAIL_ALREADY_REGISTERED` | Email already exists for this `clientId` |

---

### 2. Login

`POST /auth/login`
**Access:** Public

**Request body — `LocalLoginRequest`**

```json
{
  "email": "john@example.com",
  "password": "Password@123",
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000"
}
```

**Success — `200 OK` → `AuthResponse`**

```json
{
  "accessToken": "...",
  "refreshToken": "...",
  "tokenType": "Bearer"
}
```

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_CREDENTIALS` | Wrong email/password |
| `403` | `EMAIL_NOT_VERIFIED` | Account exists but is unverified |
| `403` | `ACCOUNT_DISABLED` | `isActive = false` |
| `404` | `USER_NOT_FOUND` | No user for this email + `clientId` |

---

### 3. Logout

`POST /auth/logout`
**Access:** Authenticated

**Headers**

```
Authorization: Bearer <accessToken>
```

Extracts the token's `jti`, blacklists it, and publishes the revocation over Redis Pub/Sub on `auth:blacklist:` channel so every subscribed tenant service invalidates the session immediately.

**Success — `204 No Content`** (empty body)

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_TOKEN` | Missing, malformed, expired, or already-blacklisted token |

---

### 4. Refresh Access Token

`POST /auth/refresh`
**Access:** Public *(requires possession of a valid refresh token)*

**Request body — `RefreshTokenRequest`**

```json
{ "refreshToken": "8f14e45f-ceea-4c3c-b8f0-9a62d2246421" }
```

Validates the refresh token, issues a new access token, rotates the refresh token's `jti` in Redis, and invalidates the previous one (reuse of an old refresh token after rotation should be treated as a compromise signal).

**Success — `200 OK` → `AuthResponse`**

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_REFRESH_TOKEN` | Token not found, expired, or already rotated/reused |

---

### 5. Verify Email

`GET /auth/verify-email?token=<verification_token>`
**Access:** Public

**Success — `200 OK`**

```json
{ "message": "Email verified successfully." }
```

**Errors**

| Status | Error | Cause |
|--------|---|---|
| `401`  | `TOKEN_NOT_FOUND` | Invalid token |
---

### 6. Resend Verification Email

`POST /auth/resend-verification`
**Access:** Public

**Request body — `ResendVerificationRequest`**

```json
{
  "email": "john@example.com",
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000"
}
```

Deletes any existing verification token and issues a new one — only if the account is not already verified.

**Success — `200 OK`**

```json
{ "message": "Verification email sent." }
```

**Errors**

| Status | Error | Cause |
|---|---|---|
| `404` | `USER_NOT_FOUND` | No matching account |

---

### 7. Forgot Password

`POST /auth/forgot-password`
**Access:** Public

**Request body — `ForgotPasswordRequest`**

```json
{
  "email": "john@example.com",
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000"
}
```

**Success — `200 OK`**

```json
{ "message": "Password reset email sent." }
```

> Note: for security, most implementations return `200` here even if the email doesn't exist, to avoid leaking which emails are registered. Decide this behavior explicitly and document it — don't let it be accidental.

---

### 8. Reset Password

`POST /auth/reset-password?token=<reset_token>`
**Access:** Public

**Request body — `ResetPasswordExecutionRequest`**

```json
{ "newPassword": "NewPassword@123" }
```

Validates the reset token, updates the password, and deletes the token (single-use).

**Success — `200 OK`**

```json
{ "message": "Password changed successfully." }
```

**Errors**

| Status | Error | Cause |
|---|---|---|
| `400` | `VALIDATION_ERROR` | Password doesn't meet policy |

---