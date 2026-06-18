package bdj.hkb.auth_service.user.dto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        UUID clientId,
        boolean isActive,
        String authProvider, // e.g., "local" or "google"
        List<String> roles,  // e.g., ["ROLE_USER", "ROLE_ADMIN"]
        OffsetDateTime createdAt
) {}