package bdj.hkb.auth_service.auth.strategy;

import bdj.hkb.auth_service.auth.OAuthProvider;

public interface OAuthProviderStrategy {
    OAuthProvider getProvider();
    String buildAuthorizationUrl(String state);
}
