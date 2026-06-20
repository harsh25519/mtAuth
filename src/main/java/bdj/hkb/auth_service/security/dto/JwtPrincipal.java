package bdj.hkb.auth_service.security.dto;

import java.util.List;
import java.util.UUID;

public record JwtPrincipal(
        UUID userId,
        UUID clientId,
        List<String> roles
) {
    public boolean hasRole(String role) {
        return roles.contains(role);
    }
}
