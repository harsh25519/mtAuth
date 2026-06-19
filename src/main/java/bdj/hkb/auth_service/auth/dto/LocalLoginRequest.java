package bdj.hkb.auth_service.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record LocalLoginRequest(
        @NotBlank @Email
        String email,

        @NotBlank
        String password,

        @NotNull
        UUID clientId
) {}
