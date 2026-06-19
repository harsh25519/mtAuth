package bdj.hkb.auth_service.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record OAuthSignupRequest(
        @NotBlank(message = "Auth provider is required (e.g., 'google', 'github')")
        String authProvider,   // "google", "github"

        @NotBlank(message = "The cryptographic token from Google/GitHub is required")
        String token,

        @NotNull(message = "Client ID is required")
        UUID clientId,

        @NotBlank(message = "Client Secret should not be blank")
        String clientSecret
) {}
