package bdj.hkb.auth_service.role.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record RevokeRoleRequest(
        @NotNull
        UUID userId,

        @NotNull
        UUID clientId,

        @NotBlank
        String role
) {
}
