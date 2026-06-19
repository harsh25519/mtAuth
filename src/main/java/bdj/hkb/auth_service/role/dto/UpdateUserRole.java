package bdj.hkb.auth_service.role.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record UpdateUserRole(

        @NotNull(message = "Enter user id")
        UUID userId,

        @NotBlank(message = "new role is required")
        String newRole
) {
}
