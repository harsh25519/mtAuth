package bdj.hkb.auth_service.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record OAuthExchangeRequest(
        @NotBlank(message = "Authorization code is required")
        String code,

        @NotNull(message = "Client ID is required")
        UUID clientId,

        @NotBlank(message = "Client Secret is required")
        String clientSecret
) {
}
