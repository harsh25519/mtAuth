## OAuth API (`/oauth`)

## Workflow

### OAuth Login Flow

```
 ┌──────────┐    ┌────────────────────────┐    ┌───────────────────┐
 │ Frontend │───▶│ POST /oauth/{provider} │───▶│ OAuth Provider   │
 │          │    │ /start                 │    │ (Google/GitHub)   │
 └──────────┘    └────────────────────────┘    └──────────┬────────┘
                                                          │ user authorizes
                                                          ▼
                                          ┌────────────────────────────────┐
                                          │ GET /oauth/{provider}/callback │
                                          │  - exchanges code w/ provider  │
                                          │  - creates local user if new   │
                                          │  - caches AuthResponse (Redis, │
                                          │    30–60s TTL)                 │
                                          │  - issues short-lived bridge   │
                                          │    code                        │
                                          └───────────────┬────────────────┘
                                                          │ redirect w/ ?code=
                                                          ▼
                                          ┌─────────────────────────────────┐
                                          │ Redirect url(client's) extracts │
                                          │ `code` from redirect URL        │
                                          └───────────────┬─────────────────┘
                                                          ▼
                                          ┌────────────────────────────────┐
                                          │ POST /oauth/exchange           │
                                          │  (server-to-server)            │
                                          └───────────────┬────────────────┘
                                                          ▼
                                          ┌────────────────────────────────┐
                                          │ AuthResponse                   │
                                          │ (access + refresh tokens)      │
                                          └────────────────────────────────┘
```


### 1. Start OAuth Login

`POST /oauth/{provider}/start?clientId=<CLIENT_UUID>`
**Access:** Public

| Path Variable | Values |
|---|---|
| `provider` | `google`, `github`, … (extensible) |

Redirects the browser to the provider's authorization page. No JSON body — this is a redirect-driven endpoint.

**Success — `302 Found`** → `Location: <provider authorization URL>`

**Errors**

| Status | Error | Cause |
|---|---|---|
| `400` | `UNSUPPORTED_PROVIDER` | Unknown `provider` path value |
| `404` | `CLIENT_NOT_FOUND` | Unregistered `clientId` |

---

### 2. OAuth Callback

`GET /oauth/{provider}/callback?code=<code>&state=<state>`
**Access:** Public (called by the OAuth provider, not the frontend directly, to the auth service.)

Exchanges the provider's authorization `code`, creates a local user record if one doesn't exist for this identity, generates an `AuthResponse`, caches it in Redis for **30–60 seconds**, and issues a short-lived, single-use bridge code. The browser is then redirected to the tenant's registered redirect URI.

**Success — `302 Found`**

```
Location: https://client.app/oauth/callback?code=<bridge_code>
```

**Errors**

| Status | Error | Cause |
|---|---|---|
| `400` | `INVALID_STATE` | `state` param mismatch — possible CSRF |
| `401` | `PROVIDER_AUTH_FAILED` | Provider rejected the code / user denied consent |

---

### 3. Exchange OAuth Code

`POST /oauth/exchange`
**Access:** Public *(requires possession of a valid, unexpired bridge code)*

**Request body — `OAuthExchangeDto`**

```json
{
  "code": "abc123",
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000",
  "clientSecret": "tenant-secret"
}
```

This is a **server-to-server call** made by the tenant's backend (not the browser), avoiding both CORS issues and exposing tokens directly in a browser-visible redirect response.

**Success — `200 OK` → `AuthResponse`**

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_CLIENT_CREDENTIALS` | Bad `clientId`/`clientSecret` |
| `404` | `CODE_NOT_FOUND` | Bridge code invalid, already used, or expired (30–60s TTL elapsed) |

---