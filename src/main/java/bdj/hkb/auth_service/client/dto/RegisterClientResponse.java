package bdj.hkb.auth_service.client.dto;

import java.util.UUID;

public record RegisterClientResponse(
        String name,
        UUID clientId,
        String clientSecret,
        String message
) {}
