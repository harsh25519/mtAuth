package bdj.hkb.auth_service.client;

import bdj.hkb.auth_service.client.dto.ClientResponse;
import bdj.hkb.auth_service.client.dto.RegisterClientRequest;
import bdj.hkb.auth_service.client.dto.RegisterClientResponse;
import bdj.hkb.auth_service.client.dto.UpdateRedirectUrlRequest;
import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.security.dto.JwtPrincipal;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/clients")
public class ClientController {

    private final ClientService clientService;
    private final JwtUtilService jwtUtilService;

    @PostMapping("/register")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<RegisterClientResponse> registerClient(
            @Valid @RequestBody RegisterClientRequest request,
            @AuthenticationPrincipal JwtPrincipal token) {

        RegisterClientResponse response = clientService.registerClient(request, token);

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
    public ResponseEntity<Page<ClientResponse>> getClients(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size);
        Page<ClientResponse> clients = clientService.getAllClients(pageable);
        return ResponseEntity.ok(clients);
    }

    @PutMapping("/update/redirect-url")
    @PreAuthorize("hasRole(ADMIN)")
    public ResponseEntity<?> updateRedirectUrl(
            @Valid @RequestBody UpdateRedirectUrlRequest request,
            @AuthenticationPrincipal JwtPrincipal token) {

        // We pass the token's Client ID to the service
        clientService.updateRedirectUrl(
                token,
                request.redirectUrl()
        );

        return ResponseEntity.ok(Map.of("message", "Redirect URL updated successfully"));
    }

}
