package bdj.hkb.auth_service.auth;

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
}