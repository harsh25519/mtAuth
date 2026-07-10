## User API (`/users`)

### A. List All Users (Platform Admin)

`GET /users`
**Access:** `AUTH_ADMIN` only

**Headers**

```
Authorization: Bearer <accessToken>
```

Authenticates the caller as an `AUTH_ADMIN` and returns **every** user across **all** tenants, paginated.

**Query params:** `page`, `size` (see [Conventions](#conventions))

**Success — `200 OK`**

```json
{
  "content": [
    {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "email": "john@example.com",
      "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000",
      "isActive": true,
      "authProvider": "LOCAL",
      "roles": ["ROLE_USER"],
      "createdAt": "2026-07-08T10:00:00Z"
    }
  ],
  "page": 0,
  "size": 20,
  "totalElements": 134,
  "totalPages": 7
}
```

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |
| `403` | `INSUFFICIENT_ROLE` | Caller is authenticated but not an `AUTH_ADMIN` |

---

### B. List Users by Client

`GET /users/client/{clientId}`
**Access:** Authenticated — scoped

**Headers**

```
Authorization: Bearer <accessToken>
```

| Path Variable | Type | Notes |
|---|---|---|
| `clientId` | UUID | Tenant whose users are being listed |

**Authorization rule:** allowed if either is true:
- the path `clientId` matches the caller's **token** `clientId` (i.e. they belong to that tenant), **or**
- the caller holds `AUTH_ADMIN`

**Query params:** `page`, `size`

**Success — `200 OK`** → paginated list of `UserResponse` (same shape as endpoint A, scoped to `clientId`)

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |
| `403` | `TENANT_MISMATCH` | Path `clientId` ≠ token `clientId`, and caller is not `AUTH_ADMIN` |
| `404` | `CLIENT_NOT_FOUND` | Unknown `clientId` |

---

### C. Get User by ID

`GET /users/{userId}`
**Access:** Authenticated — scoped

**Headers**

```
Authorization: Bearer <accessToken>
```

| Path Variable | Type |
|---|---|
| `userId` | UUID |

**Authorization rule:** allowed if either is true:
- caller holds `AUTH_ADMIN`, **or**
- the target user's `clientId` matches the caller's **token** `clientId`

**Success — `200 OK` → `UserResponse`**

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

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |
| `403` | `TENANT_MISMATCH` | Target user belongs to a different tenant than the caller, and caller is not `AUTH_ADMIN` |
| `404` | `USER_NOT_FOUND` | No user with this `userId` |

---

## User Roles API (`/users/roles`)

### `AssignRoleRequest`

```java
AssignRoleRequest(
    UUID userId,
    UUID clientId,
    String role
);
```

### `RevokeRoleRequest`

```java
RevokeRoleRequest(
    UUID userId,
    UUID clientId,
    String role
);
```

---

### A. Assign Role

`POST /users/roles`
**Access:** `CLIENT_ADMIN` (of the target client) or `AUTH_ADMIN`

**Headers**

```
Authorization: Bearer <accessToken>
```

**Request body — `AssignRoleRequest`**

```json
{
  "userId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000",
  "role": "ROLE_CLIENT_ADMIN"
}
```

**Behavior:** Resolves the caller's `JwtPrincipal`, verifies they're a `CLIENT_ADMIN` for `clientId` (or `AUTH_ADMIN`), then checks whether the target user already holds `role`. If not, inserts a new role row for that user.

**Restriction:** a caller can never grant themselves `ROLE_AUTH_ADMIN` — this is a hard-coded privilege-escalation guard, independent of role checks above.

**Success — `201 Created`**

```json
{ "message": "Role assigned successfully." }
```

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |
| `403` | `INSUFFICIENT_ROLE` | Caller is neither `CLIENT_ADMIN` of this client nor `AUTH_ADMIN` |
| `403` | `SELF_ESCALATION_FORBIDDEN` | Caller attempted to grant themselves `ROLE_AUTH_ADMIN` |
| `404` | `USER_NOT_FOUND` | Target `userId` doesn't exist |
| `422` | `ROLE_ALREADY_ASSIGNED` | User already holds this role |

---

### B. Revoke Role

`DELETE /users/roles`
**Access:** `CLIENT_ADMIN` (of the target client) or `AUTH_ADMIN`

**Headers**

```
Authorization: Bearer <accessToken>
```

**Request body — `RevokeRoleRequest`**

```json
{
  "userId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "clientId": "8f14e45f-ceea-4c3c-b8f0-000000000000",
  "role": "ROLE_CLIENT_ADMIN"
}
```

**Restriction:** a caller can never revoke their own admin role or otherwise degrade/lock themselves out — this guard applies regardless of whether the caller technically has permission to modify the target record.

**Success — `204 No Content`**

**Errors**

| Status | Error | Cause |
|---|---|---|
| `401` | `INVALID_TOKEN` | Missing/expired/blacklisted token |
| `403` | `INSUFFICIENT_ROLE` | Caller is neither `CLIENT_ADMIN` of this client nor `AUTH_ADMIN` |
| `403` | `SELF_LOCKOUT_FORBIDDEN` | Caller attempted to revoke their own role |
| `404` | `USER_NOT_FOUND` \| `ROLE_NOT_ASSIGNED` | Target user or role-assignment doesn't exist |

---