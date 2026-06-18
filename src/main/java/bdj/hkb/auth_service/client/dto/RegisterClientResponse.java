package bdj.hkb.auth_service.client.dto;

import java.util.UUID;

public record RegisterClientResponse(
        UUID clientId,
        String clientSecret,
        String name
) {}
