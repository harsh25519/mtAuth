package bdj.hkb.auth_service.client;

import bdj.hkb.auth_service.client.dto.ClientResponse;
import bdj.hkb.auth_service.client.dto.RegisterClientRequest;
import bdj.hkb.auth_service.client.dto.RegisterClientResponse;
import bdj.hkb.auth_service.security.JwtUtilService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/clients")
public class ClientController {

    private final ClientService clientService;
    private final JwtUtilService jwtUtilService;

    @PostMapping("/register")
    @PreAuthorize("hasAnyRole('USER', 'DEVELOPER')")
    public ResponseEntity<RegisterClientResponse> registerClient(
            @Valid @RequestBody RegisterClientRequest request,
            @RequestHeader("Authorization") String authHeader) {

        // Strip out "Bearer " to get the raw token
        String token = authHeader.substring(7);

        // Extract the Tenant ID from the token payload
        String tokenClientId = jwtUtilService.extractClientId(token);

        // Pass the extracted ID down to the service layer for security validation
        RegisterClientResponse response = clientService.registerClient(request, tokenClientId);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // --- NEW: Get Specific Client by ID ---
    @GetMapping("/{clientId}")
    // You might want to allow anyone with a valid token to look up a public client name
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ClientResponse> getClientById(@PathVariable UUID clientId) {

        ClientResponse client = clientService.getActiveClientById(clientId);

        // Note: It is usually safer to return a ClientResponse DTO here instead of
        // the raw Client entity so you don't accidentally leak the hashed clientSecret.
        return ResponseEntity.ok(client);
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_AUTH_ADMIN')")
    public ResponseEntity<List<ClientResponse>> getClients() {
        List<ClientResponse> clients = clientService.getAllClients();
        return ResponseEntity.ok(clients);
    }

}
