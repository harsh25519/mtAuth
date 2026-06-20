package bdj.hkb.auth_service.role;

import bdj.hkb.auth_service.role.dto.AssignRoleRequest;
import bdj.hkb.auth_service.role.dto.RevokeRoleRequest;
import bdj.hkb.auth_service.security.dto.JwtPrincipal;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("users/roles")
public class UserRoleController {
    private final UserRoleService userRoleService;

    @PostMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> assignRole(
            @Valid @RequestBody AssignRoleRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        userRoleService.assignRole(request, principal);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @DeleteMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> revokeRole(
            @Valid @RequestBody RevokeRoleRequest request,
            @AuthenticationPrincipal JwtPrincipal principal) {
        userRoleService.revokeRole(request, principal);
        return ResponseEntity.noContent().build();
    }
}
