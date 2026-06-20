package bdj.hkb.auth_service.auth.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType
) {}