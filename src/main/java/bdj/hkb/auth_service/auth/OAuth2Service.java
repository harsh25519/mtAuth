package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import bdj.hkb.auth_service.auth.dto.OAuthSignupRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class OAuth2Service {
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtilService jwtUtil;
    private final AuthService authService;

    @Value("${google.client-id}")
    private String googleClientId;

    // 1. Reusable instances for performance
    private GoogleIdTokenVerifier googleVerifier;
    private final RestTemplate restTemplate;

    // 2. Initialize the heavy Google Verifier exactly once on startup
    @PostConstruct
    public void init() {
        this.googleVerifier = new GoogleIdTokenVerifier.Builder(
                new NetHttpTransport(),
                GsonFactory.getDefaultInstance())
                .setAudience(Collections.singletonList(googleClientId))
                .build();
    }

    // A simple internal record to standardize data from different providers
    private record OAuth2UserInfo(
            String email,
            String providerId)
    {}

    // 3. Moved @Transactional here to cover the entire process safely
    @Transactional
    public AuthResponse authenticateOAuthUser(OAuthSignupRequest request) {

        // Verify client
        Client client = clientRepository.findByIdAndIsActiveTrue(request.clientId())
                .orElseThrow(() -> new RuntimeException("Invalid client"));

        if (!passwordEncoder.matches(request.clientSecret(), client.getClientSecret())) {
            throw new RuntimeException("Invalid client secret");
        }

        // Extract user info based on the provider using a Java 17 Switch
        OAuth2UserInfo userInfo = switch (request.authProvider().toLowerCase()) {
            case "google" -> verifyGoogleToken(request.token());
            case "github" -> verifyGithubToken(request.token()); // Note: the frontend sends the GitHub access_token here
            default -> throw new IllegalArgumentException(
                    "Unsupported OAuth provider: " + request.authProvider());
        };

        // Find or create user
        User user = userRepository
                .findByProviderIdAndAuthProvider(userInfo.providerId(), request.authProvider())
                .orElseGet(() -> createOAuthUser(userInfo.email(), request.authProvider(), userInfo.providerId(), client));

        // Fetch roles
        List<String> roles = userRoleRepository
                .findByUserIdAndClientId(user.getId(), client.getId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        return authService.issueTokens(user.getId().toString(), client.getId().toString(), roles);
    }

    // --- STRATEGY 1: GOOGLE ---
    private OAuth2UserInfo verifyGoogleToken(String idToken) {
        try {
            GoogleIdToken googleIdToken = googleVerifier.verify(idToken);
            if (googleIdToken == null) {
                throw new RuntimeException("Invalid Google token");
            }
            GoogleIdToken.Payload payload = googleIdToken.getPayload();
            return new OAuth2UserInfo(payload.getEmail(), payload.getSubject());
        } catch (Exception e) {
            throw new RuntimeException("Google token verification failed", e);
        }
    }

    // --- STRATEGY 2: GITHUB ---
    private OAuth2UserInfo verifyGithubToken(String accessToken) {
        try {
            // Set up the authorization header for GitHub's API
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            HttpEntity<String> entity = new HttpEntity<>("parameters", headers);

            // Make an actual HTTP call to GitHub to get the user profile
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    "https://api.github.com/user",
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            Map<String, Object> body = response.getBody();
            if (body == null)
                throw new RuntimeException("Failed to fetch GitHub profile");

            // GitHub returns the ID as a Number, not a String
            String providerId = String.valueOf(body.get("id"));
            String email = (String) body.get("email");

            // Note: If the user's GitHub email is private, body.get("email") will be null.
            // For production, you might need a secondary call to "https://api.github.com/user/emails" here.
            if (email == null) {
                email = fetchGithubPrimaryEmail(accessToken, headers);
            }

            return new OAuth2UserInfo(email, providerId);

        } catch (Exception e) {
            throw new RuntimeException("GitHub token verification failed", e);
        }
    }

    // Removed @Transactional from here (it is now on the public method)
    private User createOAuthUser(String email, String provider, String providerId, Client client) {
        User user = User.builder()
                .client(client)
                .email(email) // Could be null for GitHub if private, ensure your DB handles this or fetch explicitly
                .authProvider(provider)
                .providerId(providerId)
                .passwordHash(null)
                .isActive(true)
                .build();

        User saved = userRepository.save(user);

        userRoleRepository.save(UserRole.builder()
                .user(saved)
                .client(client)
                .role("ROLE_USER")
                .build());

        return saved;
    }

    private String fetchGithubPrimaryEmail(String accessToken, HttpHeaders headers) {
        HttpEntity<String> entity = new HttpEntity<>("parameters", headers);

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                "https://api.github.com/user/emails",
                HttpMethod.GET,
                entity,
                new ParameterizedTypeReference<>() {}
        );

        List<Map<String, Object>> emails = response.getBody();
        if (emails == null) {
            throw new RuntimeException("Failed to fetch GitHub emails");
        }

        return emails.stream()
                .filter(e -> Boolean.TRUE.equals(e.get("primary")))
                .map(e -> (String) e.get("email"))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No primary email found"));
    }
}
