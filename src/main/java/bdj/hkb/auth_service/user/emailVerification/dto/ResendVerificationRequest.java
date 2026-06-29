package bdj.hkb.auth_service.user.emailVerification.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record ResendVerificationRequest(
        @Email(message = "Must be a valid email")
        String email,

        @NotNull(message = "Client ID is required")
        UUID clientId
) {}