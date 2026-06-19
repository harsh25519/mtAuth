package bdj.hkb.auth_service.security.dto;

import java.util.UUID;

public record JwtPrincipal(
        UUID userId,
        UUID clientId
) {}
