package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.LocalLoginRequest;
import bdj.hkb.auth_service.auth.dto.LocalSignupRequest;
import bdj.hkb.auth_service.auth.dto.OAuthSignupRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.http.auth.InvalidCredentialsException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final OAuth2Service oAuth2Service;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(
            @Valid @RequestBody LocalSignupRequest request) {
        AuthResponse response = authService.registerLocalUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LocalLoginRequest request) throws InvalidCredentialsException {
        AuthResponse response = authService.authenticateLocalUser(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/oauth-login")
    public ResponseEntity<AuthResponse> oauthLogin(
            @Valid @RequestBody OAuthSignupRequest request) {
        AuthResponse response = oAuth2Service.authenticateOAuthUser(request);
        return ResponseEntity.ok(response);
    }

}
