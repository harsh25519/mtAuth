package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.UUID;

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuthOrchestratorService orchestratorService;

    @GetMapping("/{provider}/start")
    public ResponseEntity<Void> startOAuth(
            @PathVariable("provider") String providerStr,
            @RequestParam("clientId") String clientIdStr) {

        // Safely parse the enum and UUID
        OAuthProvider provider = OAuthProvider.valueOf(providerStr.toUpperCase());
        UUID clientId = UUID.fromString(clientIdStr);

        // Let the orchestrator handle the logic
        String authUrl = orchestratorService.getAuthorizationUrl(provider, clientId);

        // Return a 302 Found redirect
        return ResponseEntity
                .status(HttpStatus.FOUND)
                .location(URI.create(authUrl))
                .build();
    }

    /**
     * GET /oauth/{provider}/callback
     * GitHub or Google redirects the browser back HERE after successful login.
     */
    @GetMapping("/{provider}/callback")
    public ResponseEntity<AuthResponse> oauthCallback(
            @PathVariable("provider") String providerStr,
            @RequestParam("code") String providerCode,
            @RequestParam("state") String state) {

        OAuthProvider provider = OAuthProvider.valueOf(providerStr.toUpperCase());

        // Process the login, create the user, and get the tokens
        AuthResponse authResponse = orchestratorService.handleProviderCallback(provider, providerCode, state);

        // Return 200 OK with the tokens directly to the screen
        return ResponseEntity.ok(authResponse);
    }
}