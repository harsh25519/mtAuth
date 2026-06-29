package bdj.hkb.auth_service.auth.dto;

public record OAuth2UserInfo(
        String email,
        String providerId
) {
}
