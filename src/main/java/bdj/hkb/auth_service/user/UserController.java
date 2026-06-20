package bdj.hkb.auth_service.user;

import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserController {

    private final UserService userService;
    private final JwtUtilService jwtUtil;

    // --- 1. Master Platform Admin: Get ALL users across ALL tenants ---
    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_AUTH_ADMIN')") // Adjust roles based on your platform's master roles
    public ResponseEntity<Page<UserResponse>> getAllUsers(
            @RequestHeader("Authorization") String authHeader,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        // 1. Extract Identity
        String tokenClientId = extractClientId(authHeader);

        // 2. Build Pagination Request
        Pageable pageable = PageRequest.of(page, size);

        // 3. Hand off to Service (Security Vault)
        Page<UserResponse> users = userService.getAllUsers(tokenClientId, pageable);

        return ResponseEntity.ok(users);
    }

    // --- 2. Tenant Admin: Get paginated users for their specific app ---
    @GetMapping("/client/{clientId}")
    @PreAuthorize("isAuthenticated()") // Front door check; Service handles the strict tenant check
    public ResponseEntity<Page<UserResponse>> getUsersByClientId(
            @PathVariable UUID clientId,
            @RequestHeader("Authorization") String authHeader,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        String tokenClientId = extractClientId(authHeader);
        Pageable pageable = PageRequest.of(page, size);

        Page<UserResponse> users = userService.getUsersByClientId(clientId, tokenClientId, pageable);

        return ResponseEntity.ok(users);
    }

    // --- 3. Single User Lookup ---
    @GetMapping("/{userId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getUserById(
            @PathVariable UUID userId,
            @RequestHeader("Authorization") String authHeader) {

        String tokenClientId = extractClientId(authHeader);

        // Note: Make sure the getUserById method in your UserService was also updated to take tokenClientId!
        UserResponse user = userService.getUserById(userId, tokenClientId);

        return ResponseEntity.ok(user);
    }

    // --- Helper Method for Clean Extraction ---
    private String extractClientId(String authHeader) {
        // Strip out the "Bearer " prefix to isolate the cryptographic token
        String token = authHeader.substring(7);
        return jwtUtil.extractClientId(token);
    }
}
