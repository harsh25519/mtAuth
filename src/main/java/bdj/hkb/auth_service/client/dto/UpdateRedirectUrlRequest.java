package bdj.hkb.auth_service.client.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record UpdateRedirectUrlRequest(
        @NotBlank(message = "Redirect URL cannot be empty")
        // Optional: You can even use Regex to enforce HTTPS/localhost at the DTO level!
        @Pattern(regexp = "^(https://.*|http://localhost:.*)$", message = "Must be a secure HTTPS URL or localhost")
        String redirectUrl
) {
}
