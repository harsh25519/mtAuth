package bdj.hkb.auth_service.auth.dto;

public record AuthResponse(
        String token,
        String tokenType
) {}