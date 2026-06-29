package bdj.hkb.auth_service.auth.strategy;

import bdj.hkb.auth_service.auth.OAuthProvider;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;

public interface OAuthProviderStrategy {
    OAuthProvider getProvider();
    String buildAuthorizationUrl(String state);
    OAuth2UserInfo fetchUserInfo(String code);
}
