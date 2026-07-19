package bdj.hkb.auth_service.ratelimit;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum RateLimitPolicy {

    LOGIN("/auth/login", "POST"),
    SIGNUP("/auth/signup", "POST"),
    FORGOT_PASSWORD("/auth/forgot-password", "POST"),
    REFRESH_TOKEN("/auth/refresh", "POST");

    private final String uri;
    private final String method;

    public static RateLimitPolicy resolve(String uri, String method) {
        for (RateLimitPolicy policy : values()) {
            if (policy.uri.equals(uri) && policy.method.equalsIgnoreCase(method)) {
                return policy;
            }
        }
        return null;
    }

}
