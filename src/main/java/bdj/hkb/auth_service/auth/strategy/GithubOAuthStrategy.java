package bdj.hkb.auth_service.auth.strategy;

import bdj.hkb.auth_service.auth.OAuthProvider;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Component
public class GithubOAuthStrategy implements OAuthProviderStrategy {

    private final RestTemplate restTemplate;
    @Value("${github.client-id}")
    private String clientId;

    @Value("${github.client-secret}")
    private String clientSecret;

    @Value("${github.redirect-uri}")
    private String redirectUri;

    public GithubOAuthStrategy(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public OAuthProvider getProvider() {
        return OAuthProvider.GITHUB;
    }

    @Override
    public String buildAuthorizationUrl(String state) {
        return "https://github.com/login/oauth/authorize" +
                "?client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&scope=user:email" +
                "&state=" + state;
    }

    @Override
    public OAuth2UserInfo fetchUserInfo(String code) {
        // 1. Exchange code for Token
        String tokenUrl = "https://github.com/login/oauth/access_token";
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("code", code);
        body.add("redirect_uri", redirectUri);

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUrl, new HttpEntity<>(body, headers), Map.class);
        String accessToken = (String) tokenResponse.getBody().get("access_token");

        if (accessToken == null) throw new RuntimeException("Failed to retrieve GitHub token");

        HttpHeaders authHeaders = new HttpHeaders();
        authHeaders.setBearerAuth(accessToken);
        HttpEntity<Void> authRequest = new HttpEntity<>(authHeaders);

        // 2. Fetch Real Provider ID
        ResponseEntity<Map> userResponse = restTemplate.exchange("https://api.github.com/user", HttpMethod.GET, authRequest, Map.class);
        // GitHub IDs are integers, convert to String
        String providerId = String.valueOf(userResponse.getBody().get("id"));

        // 3. Fetch Primary Email
        ResponseEntity<List> emailResponse = restTemplate.exchange("https://api.github.com/user/emails", HttpMethod.GET, authRequest, List.class);
        String primaryEmail = null;
        for (Object item : emailResponse.getBody()) {
            Map<String, Object> emailObj = (Map<String, Object>) item;
            if ((Boolean) emailObj.get("primary")) {
                primaryEmail = (String) emailObj.get("email");
                break;
            }
        }

        if (primaryEmail == null) throw new RuntimeException("No primary email found");

        return new OAuth2UserInfo(primaryEmail, providerId);
    }
}
