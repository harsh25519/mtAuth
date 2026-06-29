package bdj.hkb.auth_service.user.passwordReset.dto;

import jakarta.validation.constraints.NotBlank;

public record ResetPasswordExecutionRequest(

        @NotBlank(message = "New password cannot be blank")
        String newPassword
) {
}
