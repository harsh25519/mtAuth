package bdj.hkb.auth_service.userRole;

import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.exceptionHandler.AccessDeniedException;
import bdj.hkb.auth_service.exceptionHandler.RoleNotFoundException;
import bdj.hkb.auth_service.exceptionHandler.UserNotFoundException;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.role.UserRoleService;
import bdj.hkb.auth_service.role.dto.AssignRoleRequest;
import bdj.hkb.auth_service.role.dto.RevokeRoleRequest;
import bdj.hkb.auth_service.security.dto.JwtPrincipal;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserRoleServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserRoleRepository userRoleRepository;

    @InjectMocks
    private UserRoleService userRoleService;

    @Captor
    private ArgumentCaptor<UserRole> roleCaptor;

    // --- Constants ---
    private static final UUID TARGET_USER_ID = UUID.randomUUID();
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final UUID OTHER_CLIENT_ID = UUID.randomUUID();

    private static final UUID ADMIN_ID = UUID.randomUUID();
    private static final UUID GLOBAL_ADMIN_ID = UUID.randomUUID();

    private static final String ROLE_AUTH_ADMIN = "ROLE_AUTH_ADMIN";
    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String ROLE_USER = "ROLE_USER";

    // --- Principals ---
    private JwtPrincipal globalAdminPrincipal;
    private JwtPrincipal tenantAdminPrincipal;
    private JwtPrincipal unauthorizedPrincipal;

    private User targetUser;
    private Client targetClient;

    @BeforeEach
    void setUp() {
        // Principals setup
        globalAdminPrincipal = new JwtPrincipal(GLOBAL_ADMIN_ID, CLIENT_ID, List.of(ROLE_AUTH_ADMIN));
        tenantAdminPrincipal = new JwtPrincipal(ADMIN_ID, CLIENT_ID, List.of(ROLE_ADMIN));
        unauthorizedPrincipal = new JwtPrincipal(UUID.randomUUID(), CLIENT_ID, List.of(ROLE_USER));

        // Entity setup
        targetClient = Client.builder().id(CLIENT_ID).build();
        targetUser = User.builder().id(TARGET_USER_ID).client(targetClient).build();
    }

    // ==========================================
    // Tests for assignRole()
    // ==========================================

    @Test
    @DisplayName("assignRole - Should assign role successfully and normalize input")
    void assignRole_WhenValidRequest_ShouldNormalizeAndSave() {
        // Arrange (Fixed parameter order: userId, clientId, role)
        AssignRoleRequest request = new AssignRoleRequest(TARGET_USER_ID, CLIENT_ID, "user");

        when(userRepository.findByIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(Optional.of(targetUser));
        when(userRoleRepository.findByUserIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(List.of());

        // Act
        userRoleService.assignRole(request, tenantAdminPrincipal);

        // Assert
        verify(userRoleRepository).save(roleCaptor.capture());
        UserRole savedRole = roleCaptor.getValue();
        assertThat(savedRole.getRole()).isEqualTo(ROLE_USER);
        assertThat(savedRole.getUser()).isEqualTo(targetUser);
    }

    @Test
    @DisplayName("assignRole - Should return early (idempotent) if user already has the role")
    void assignRole_WhenUserAlreadyHasRole_ShouldDoNothing() {
        // Arrange (Fixed parameter order)
        AssignRoleRequest request = new AssignRoleRequest(TARGET_USER_ID, CLIENT_ID, ROLE_USER);
        UserRole existingRole = UserRole.builder().role(ROLE_USER).build();

        when(userRepository.findByIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(Optional.of(targetUser));
        when(userRoleRepository.findByUserIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(List.of(existingRole));

        // Act
        userRoleService.assignRole(request, tenantAdminPrincipal);

        // Assert
        verify(userRoleRepository, never()).save(any());
    }

    @Test
    @DisplayName("assignRole - Should throw exception for cross-tenant unauthorized request")
    void assignRole_WhenUnauthorizedPrincipal_ShouldThrowException() {
        // Arrange (Fixed parameter order)
        AssignRoleRequest request = new AssignRoleRequest(TARGET_USER_ID, OTHER_CLIENT_ID, ROLE_USER);

        // Act & Assert
        AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> {
            userRoleService.assignRole(request, unauthorizedPrincipal);
        });

        assertThat(exception.getMessage()).contains("You are not allowed to manage roles");
        verify(userRepository, never()).findByIdAndClientId(any(), any());
    }

    @Test
    @DisplayName("assignRole - Should prevent privilege escalation by tenant admin")
    void assignRole_WhenTenantAdminAssignsAuthAdmin_ShouldThrowException() {
        // Arrange (Fixed parameter order)
        AssignRoleRequest request = new AssignRoleRequest(TARGET_USER_ID, CLIENT_ID, ROLE_AUTH_ADMIN);

        // Act & Assert
        AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> {
            userRoleService.assignRole(request, tenantAdminPrincipal);
        });

        assertThat(exception.getMessage()).contains("Only a platform admin can grant " + ROLE_AUTH_ADMIN);
        verify(userRepository, never()).findByIdAndClientId(any(), any());
    }

    @Test
    @DisplayName("assignRole - Should allow platform admin to assign AUTH_ADMIN role")
    void assignRole_WhenGlobalAdminAssignsAuthAdmin_ShouldSucceed() {
        // Arrange (Fixed parameter order)
        AssignRoleRequest request = new AssignRoleRequest(TARGET_USER_ID, CLIENT_ID, ROLE_AUTH_ADMIN);

        when(userRepository.findByIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(Optional.of(targetUser));
        when(userRoleRepository.findByUserIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(List.of());

        // Act
        userRoleService.assignRole(request, globalAdminPrincipal);

        // Assert
        verify(userRoleRepository).save(any(UserRole.class));
    }

    @Test
    @DisplayName("assignRole - Should throw UserNotFoundException if user doesn't exist for client")
    void assignRole_WhenUserNotFound_ShouldThrowException() {
        // Arrange (Fixed parameter order)
        AssignRoleRequest request = new AssignRoleRequest(TARGET_USER_ID, CLIENT_ID, ROLE_USER);
        when(userRepository.findByIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(UserNotFoundException.class, () -> {
            userRoleService.assignRole(request, tenantAdminPrincipal);
        });
    }

    // ==========================================
    // Tests for revokeRole()
    // ==========================================

    @Test
    @DisplayName("revokeRole - Should successfully revoke an existing role")
    void revokeRole_WhenValidRequest_ShouldDeleteRole() {
        // Arrange (Fixed parameter order: userId, clientId, role)
        RevokeRoleRequest request = new RevokeRoleRequest(TARGET_USER_ID, CLIENT_ID, ROLE_USER);
        UserRole existingRole = UserRole.builder().role(ROLE_USER).build();

        when(userRoleRepository.findByUserIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(List.of(existingRole));

        // Act
        userRoleService.revokeRole(request, tenantAdminPrincipal);

        // Assert
        verify(userRoleRepository).delete(existingRole);
    }

    @Test
    @DisplayName("revokeRole - Should throw AccessDeniedException on Self-Lockout attempt")
    void revokeRole_WhenSelfLockoutAttempted_ShouldThrowException() {
        // Arrange (Fixed parameter order)
        RevokeRoleRequest request = new RevokeRoleRequest(ADMIN_ID, CLIENT_ID, ROLE_ADMIN);

        // Act & Assert
        AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> {
            userRoleService.revokeRole(request, tenantAdminPrincipal);
        });

        assertThat(exception.getMessage()).contains("You cannot revoke your own admin privileges");
        verify(userRoleRepository, never()).delete(any());
    }

    @Test
    @DisplayName("revokeRole - Should allow self-revocation of non-protected roles")
    void revokeRole_WhenRevokingOwnStandardRole_ShouldSucceed() {
        // Arrange (Fixed parameter order)
        RevokeRoleRequest request = new RevokeRoleRequest(ADMIN_ID, CLIENT_ID, ROLE_USER);
        UserRole existingStandardRole = UserRole.builder().role(ROLE_USER).build();

        when(userRoleRepository.findByUserIdAndClientId(ADMIN_ID, CLIENT_ID))
                .thenReturn(List.of(existingStandardRole));

        // Act
        userRoleService.revokeRole(request, tenantAdminPrincipal);

        // Assert
        verify(userRoleRepository).delete(existingStandardRole);
    }

    @Test
    @DisplayName("revokeRole - Should throw RoleNotFoundException if user doesn't have the role")
    void revokeRole_WhenRoleDoesNotExistOnUser_ShouldThrowException() {
        // Arrange (Fixed parameter order)
        RevokeRoleRequest request = new RevokeRoleRequest(TARGET_USER_ID, CLIENT_ID, "ROLE_SUPER_USER");
        UserRole existingRole = UserRole.builder().role(ROLE_USER).build();

        when(userRoleRepository.findByUserIdAndClientId(TARGET_USER_ID, CLIENT_ID)).thenReturn(List.of(existingRole));

        // Act & Assert
        assertThrows(RoleNotFoundException.class, () -> {
            userRoleService.revokeRole(request, tenantAdminPrincipal);
        });

        verify(userRoleRepository, never()).delete(any());
    }
}