package bdj.hkb.auth_service.auth.dto;

public record TokenResponse(
        String accessToken,
        String tokenType,
        Long expiresIn
) {}