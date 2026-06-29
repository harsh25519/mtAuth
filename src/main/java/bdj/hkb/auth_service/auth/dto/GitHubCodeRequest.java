package bdj.hkb.auth_service.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record GitHubCodeRequest (
        @NotBlank String code,
        @NotNull UUID clientId,
        @NotBlank String clientSecret
){
}
