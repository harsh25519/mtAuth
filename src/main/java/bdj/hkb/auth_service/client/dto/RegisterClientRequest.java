package bdj.hkb.auth_service.client.dto;

import jakarta.validation.constraints.NotBlank;

public record RegisterClientRequest(
        @NotBlank
        String name,

        @NotBlank
        String redirectUrl
) {}
