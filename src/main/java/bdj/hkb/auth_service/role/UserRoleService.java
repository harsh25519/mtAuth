package bdj.hkb.auth_service.role;

import bdj.hkb.auth_service.exceptionHandler.AccessDeniedException;
import bdj.hkb.auth_service.exceptionHandler.RoleNotFoundException;
import bdj.hkb.auth_service.exceptionHandler.UserNotFoundException;
import bdj.hkb.auth_service.role.dto.AssignRoleRequest;
import bdj.hkb.auth_service.role.dto.RevokeRoleRequest;
import bdj.hkb.auth_service.security.dto.JwtPrincipal;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserRoleService {

    private static final String ROLE_AUTH_ADMIN = "ROLE_AUTH_ADMIN";
    private static final String ROLE_CLIENT_ADMIN = "ROLE_ADMIN";
    private static final Set<String> LOCKOUT_PROTECTED_ROLES =
            Set.of(ROLE_AUTH_ADMIN, ROLE_CLIENT_ADMIN);

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Transactional
    public void assignRole(AssignRoleRequest request, JwtPrincipal principal) {
        authorizeRoleChange(request.clientId(), principal);

        String normalizedRole = normalizeRole(request.role());

        // Privilege escalation guard — only a platform admin can grant platform-admin
        if (normalizedRole.equals(ROLE_AUTH_ADMIN) && !principal.hasRole(ROLE_AUTH_ADMIN)) {
            throw new AccessDeniedException("Only a platform admin can grant " + ROLE_AUTH_ADMIN);
        }

        User user = userRepository.findByIdAndClientId(request.userId(), request.clientId())
                .orElseThrow(() -> new UserNotFoundException("User not found for this client"));

        boolean alreadyHasRole = userRoleRepository
                .findByUserIdAndClientId(request.userId(), request.clientId())
                .stream()
                .anyMatch(ur -> ur.getRole().equals(normalizedRole));

        if (alreadyHasRole) {
            return; // idempotent
        }

        UserRole newRole = UserRole.builder()
                .user(user)
                .client(user.getClient())
                .role(normalizedRole)
                .build();

        userRoleRepository.save(newRole);
    }

    @Transactional
    public void revokeRole(RevokeRoleRequest request, JwtPrincipal principal) {
        authorizeRoleChange(request.clientId(), principal);

        String normalizedRole = normalizeRole(request.role());

        // Self-lockout guard — covers both admin tiers
        boolean isTargetingSelf = principal.userId().equals(request.userId());
        if (isTargetingSelf && LOCKOUT_PROTECTED_ROLES.contains(normalizedRole)) {
            throw new AccessDeniedException(
                    "You cannot revoke your own admin privileges. Ask another admin to do this.");
        }

        List<UserRole> roles = userRoleRepository
                .findByUserIdAndClientId(request.userId(), request.clientId());

        UserRole toRemove = roles.stream()
                .filter(ur -> ur.getRole().equals(normalizedRole))
                .findFirst()
                .orElseThrow(() -> new RoleNotFoundException(
                        "User does not have role: " + normalizedRole));

        userRoleRepository.delete(toRemove);
    }

    private String normalizeRole(String rawRole) {
        String upperRole = rawRole.trim().toUpperCase();
        return upperRole.startsWith("ROLE_") ? upperRole : "ROLE_" + upperRole;
    }

    private void authorizeRoleChange(UUID clientId, JwtPrincipal principal) {
        boolean isGlobalAdmin = principal.hasRole(ROLE_AUTH_ADMIN);
        boolean isSameTenantAdmin = clientId.equals(principal.clientId())
                && principal.hasRole(ROLE_CLIENT_ADMIN);

        if (!isGlobalAdmin && !isSameTenantAdmin) {
            throw new AccessDeniedException("You are not allowed to manage roles for this client");
        }
    }
}