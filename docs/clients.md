## Client API (`/clients`)


### `ClientResponse`

```json
{
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000",
  "name": "Acme Corp",
  "isActive": true,
  "createdAt": "2026-06-01T09:00:00Z"
}
```

### `RegisterClientRequest`

```java
RegisterClientRequest(
    String name,
    String redirectUrl
);
```

### `RegisterClientResponse`

```json
{
  "clientName": "Acme Corp",
  "id": "8f14e45f-ceea-4c3c-b8f0-000000000000",
  "clientSecret": "a-long-random-secret",
  "warning": "This secret will only be shown once. Store it securely."
}
```

### `UpdateRedirectUrlRequest`

```java
UpdateRedirectUrlRequest(
    String newUrl
);
```

---

### A. Register Client

`POST /clients/register`
**Access:** Authenticated (any registered user of the auth service)

**Headers**

```
Authorization: Bearer <accessToken>
```

**Request body — `RegisterClientRequest`**

```json
{
  "name": "Acme Corp",
  "redirectUrl": "https://acme.app/oauth/callback"
}
```

**Behavior:** Creates a new tenant (`Client`) with the given `name` and `redirectUrl`, and automatically makes the requesting user the `CLIENT_ADMIN` of the newly created client.

**Success — `201 Created` → `RegisterClientResponse`**

```json
{
  "clientName": "Acme Corp",
  "id": "8f14e45f-ceea-4c3c-b8f0-000000000000",
  "clientSecret": "a-long-random-secret",
  "warning": "This secret will only be shown once. Store it securely."
}
```

> ⚠️ The `clientSecret` is returned exactly once, at creation time. It is not retrievable afterward — implement a rotate/regenerate endpoint if lost secrets need recovery.

**Errors**

| Status | Error | Cause |
|---|---|---|
| `400` | `VALIDATION_ERROR` | Missing/invalid `name` or `redirectUrl` |
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |

---

### B. Get Client by ID

`GET /clients/{clientId}`
**Access:** Authenticated

**Headers**

```
Authorization: Bearer <accessToken>
```

Looks up the client by ID where `isActive = true` and returns it.

**Success — `200 OK` → `ClientResponse`**

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |
| `404` | `CLIENT_NOT_FOUND` | No active client with this ID |

---

### C. List All Clients (Platform Admin)

`GET /clients`
**Access:** `AUTH_ADMIN` only

**Headers**

```
Authorization: Bearer <accessToken>
```

**Query params:** `page`, `size`

**Success — `200 OK`** → paginated list of `ClientResponse`

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |
| `403` | `INSUFFICIENT_ROLE` | Caller is not `AUTH_ADMIN` |

---

### D. Update Redirect URL

`PUT /clients/update/redirect-url`
**Access:** `CLIENT_ADMIN` of the client only

**Headers**

```
Authorization: Bearer <accessToken>
```

**Request body — `UpdateRedirectUrlRequest`**

```json
{ "newUrl": "https://acme.app/new-oauth-callback" }
```

**Behavior:** Resolves the client from the caller's **token** `clientId` (not a path/body param — an admin can only update their own client's redirect URL), sets the new URL, and persists it.

**Success — `200 OK`**

```json
{ "message": "Redirect URL updated successfully." }
```

**Errors**

| Status | Error | Cause |
|---|---|---|
| `400` | `VALIDATION_ERROR` | `newUrl` missing or not a valid URL |
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |
| `403` | `INSUFFICIENT_ROLE` | Caller is not `CLIENT_ADMIN` of their own client |

---