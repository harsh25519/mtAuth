package bdj.hkb.auth_service.user.passwordReset.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record ForgotPasswordRequest(
        @Email(message = "Must be a valid email")
        String email,

        @NotNull(message = "Client ID is required")
        UUID clientId
){
}
