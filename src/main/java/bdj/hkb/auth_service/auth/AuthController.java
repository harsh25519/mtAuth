package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.LocalLoginRequest;
import bdj.hkb.auth_service.auth.dto.LocalSignupRequest;
import bdj.hkb.auth_service.security.dto.RefreshTokenRequest;
import bdj.hkb.auth_service.user.emailVerification.EmailVerificationService;
import bdj.hkb.auth_service.user.emailVerification.dto.ResendVerificationRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.http.auth.InvalidCredentialsException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final EmailVerificationService emailVerificationService;
    private final LocalAuthOrchestrator localAuthOrchestrator;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(
            @Valid @RequestBody LocalSignupRequest request) {
        // The Controller simply hands the validated request to the Orchestrator
        localAuthOrchestrator.registerUserAndDispatchEmail(request);

        // And returns the success response
        return ResponseEntity.ok(Map.of(
                "message", "Registration successful. Please check your email to verify your account."
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LocalLoginRequest request) throws InvalidCredentialsException {
        AuthResponse response = authService.authenticateLocalUser(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7);
        authService.logout(token);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody @Valid RefreshTokenRequest request) {
        AuthResponse response = authService.refreshAccessToken(request.refreshToken());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam("token") String token) {

        // This will throw a RuntimeException if the token is invalid or expired
        emailVerificationService.verifyEmail(token);

        return ResponseEntity.ok(Map.of(
                "message", "Email verified successfully. You can now log in."
        ));
    }

    /**
     * POST /auth/resend-verification
     * Generates and emails a fresh verification token for unverified users.
     */
    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request) {

        localAuthOrchestrator.resendVerificationEmail(request);

        return ResponseEntity.ok(Map.of(
                "message", "If an account exists and is unverified, a new link has been sent."
        ));
    }

}
