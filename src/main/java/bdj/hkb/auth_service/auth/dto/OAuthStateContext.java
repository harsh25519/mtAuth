package bdj.hkb.auth_service.auth.dto;

import bdj.hkb.auth_service.auth.OAuthProvider;

import java.util.UUID;

public record OAuthStateContext(
        UUID clientId,
        OAuthProvider provider,
        long timestamp
) {
}
