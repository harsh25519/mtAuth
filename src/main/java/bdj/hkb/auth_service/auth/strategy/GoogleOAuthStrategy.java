package bdj.hkb.auth_service.auth.strategy;

import bdj.hkb.auth_service.auth.OAuthProvider;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Component
public class GoogleOAuthStrategy implements OAuthProviderStrategy {

    private final RestTemplate restTemplate;
    @Value("${google.client-id}")
    private String clientId;

    @Value("${google.client-secret}")
    private String clientSecret;

    @Value("${google.redirect-uri}")
    private String redirectUri;

    public GoogleOAuthStrategy(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public OAuthProvider getProvider() {
        return OAuthProvider.GOOGLE;
    }

    @Override
    public String buildAuthorizationUrl(String state) {
        return "https://accounts.google.com/o/oauth2/v2/auth" +
                "?client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&response_type=code" +
                "&scope=email%20profile" +
                "&access_type=offline" +
                "&state=" + state +
                "&prompt=consent";
    }

    @Override
    public OAuth2UserInfo fetchUserInfo(String code) {
        // 1. Exchange code for Google Access Token
        String tokenUrl = "https://oauth2.googleapis.com/token";

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("code", code);
        body.add("redirect_uri", redirectUri);
        body.add("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, new HttpEntity<>(body, headers), Map.class);
        String accessToken = (String) tokenResponse.getBody().get("access_token");

        if (accessToken == null) throw new RuntimeException("Failed to retrieve Google token");

        // 2. Fetch User Profile (Google provides ID and Email in one shot)
        String userInfoUrl = "https://www.googleapis.com/oauth2/v3/userinfo";
        HttpHeaders authHeaders = new HttpHeaders();
        authHeaders.setBearerAuth(accessToken);

        ResponseEntity<Map> userResponse = restTemplate.exchange(userInfoUrl, HttpMethod.GET, new HttpEntity<>(authHeaders), Map.class);

        String email = (String) userResponse.getBody().get("email");
        String providerId = (String) userResponse.getBody().get("sub"); // Google calls their ID "sub" (Subject)

        if (email == null || providerId == null) {
            throw new RuntimeException("Failed to retrieve email or provider ID from Google");
        }

        return new OAuth2UserInfo(email, providerId);
    }
}
