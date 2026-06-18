package bdj.hkb.auth_service.client.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

public record ClientResponse(
        UUID id,
        String name,
        Boolean isActive,
        OffsetDateTime createdAt
) {
}
