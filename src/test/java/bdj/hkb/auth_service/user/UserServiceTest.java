package bdj.hkb.auth_service.user;

import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.exceptionHandler.UserNotFoundException;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.user.dto.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserRoleRepository userRoleRepository;

    @InjectMocks
    private UserService userService;

    // --- Test Constants ---
    private static final String MASTER_CLIENT_ID = "master-admin-uuid-1234";
    private static final UUID TENANT_CLIENT_ID = UUID.randomUUID();
    private static final UUID OTHER_TENANT_CLIENT_ID = UUID.randomUUID();
    private static final UUID USER_ID = UUID.randomUUID();
    private static final String EMAIL = "testuser@example.com";
    private static final String ROLE_NAME = "ROLE_USER";

    private Client tenantClient;
    private User mockUser;
    private UserRole mockUserRole;
    private Pageable defaultPageable;

    @BeforeEach
    void setUp() {
        // Inject the @Value property using Spring's Reflection utility
        ReflectionTestUtils.setField(userService, "masterClientId", MASTER_CLIENT_ID);

        defaultPageable = PageRequest.of(0, 10);

        tenantClient = Client.builder()
                .id(TENANT_CLIENT_ID)
                .name("Tenant App")
                .build();

        mockUser = User.builder()
                .id(USER_ID)
                .client(tenantClient)
                .email(EMAIL)
                .isActive(true)
                .authProvider("LOCAL")
                .createdAt(OffsetDateTime.now())
                .build();

        mockUserRole = UserRole.builder()
                .id(UUID.randomUUID())
                .user(mockUser)
                .client(tenantClient)
                .role(ROLE_NAME)
                .build();
    }

    // ==========================================
    // Tests for getAllUsers()
    // ==========================================

    @Test
    @DisplayName("getAllUsers - Should return paginated users when requested by Master Admin")
    void getAllUsers_WhenMasterAdmin_ShouldReturnAllUsers() {
        // Arrange
        Page<User> mockPage = new PageImpl<>(List.of(mockUser));
        when(userRepository.findAllWithClient(defaultPageable)).thenReturn(mockPage);
        when(userRoleRepository.findByUserIds(List.of(USER_ID))).thenReturn(List.of(mockUserRole));

        // Act
        Page<UserResponse> result = userService.getAllUsers(MASTER_CLIENT_ID, defaultPageable);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getTotalElements()).isEqualTo(1);

        UserResponse response = result.getContent().get(0);
        assertThat(response.email()).isEqualTo(EMAIL); // Assuming UserResponse is a record, use .email()
        assertThat(response.roles()).containsExactly(ROLE_NAME);

        verify(userRepository, times(1)).findAllWithClient(defaultPageable);
    }

    @Test
    @DisplayName("getAllUsers - Should throw AccessDeniedException if not Master Admin")
    void getAllUsers_WhenNotMasterAdmin_ShouldThrowException() {
        // Act & Assert
        AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> {
            userService.getAllUsers(TENANT_CLIENT_ID.toString(), defaultPageable);
        });

        assertThat(exception.getMessage()).contains("Only platform admins can view all users globally.");

        verify(userRepository, never()).findAllWithClient(any());
    }

    // ==========================================
    // Tests for getUsersByClientId()
    // ==========================================

    @Test
    @DisplayName("getUsersByClientId - Should return users when requesting own tenant")
    void getUsersByClientId_WhenOwnTenant_ShouldReturnUsers() {
        // Arrange
        Page<User> mockPage = new PageImpl<>(List.of(mockUser));
        when(userRepository.findByClientIdWithClient(TENANT_CLIENT_ID, defaultPageable)).thenReturn(mockPage);
        when(userRoleRepository.findByUserIds(List.of(USER_ID))).thenReturn(List.of(mockUserRole));

        // Act
        Page<UserResponse> result = userService.getUsersByClientId(TENANT_CLIENT_ID, TENANT_CLIENT_ID.toString(), defaultPageable);

        // Assert
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getContent().get(0).email()).isEqualTo(EMAIL);
    }

    @Test
    @DisplayName("getUsersByClientId - Should return users when requested by Master Admin")
    void getUsersByClientId_WhenMasterAdmin_ShouldReturnUsers() {
        // Arrange
        Page<User> mockPage = new PageImpl<>(List.of(mockUser));
        when(userRepository.findByClientIdWithClient(TENANT_CLIENT_ID, defaultPageable)).thenReturn(mockPage);
        when(userRoleRepository.findByUserIds(List.of(USER_ID))).thenReturn(List.of(mockUserRole));

        // Act
        Page<UserResponse> result = userService.getUsersByClientId(TENANT_CLIENT_ID, MASTER_CLIENT_ID, defaultPageable);

        // Assert
        assertThat(result.getTotalElements()).isEqualTo(1);
    }

    @Test
    @DisplayName("getUsersByClientId - Should throw AccessDeniedException for cross-tenant request")
    void getUsersByClientId_WhenDifferentTenant_ShouldThrowException() {
        // Act & Assert
        AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> {
            userService.getUsersByClientId(TENANT_CLIENT_ID, OTHER_TENANT_CLIENT_ID.toString(), defaultPageable);
        });

        assertThat(exception.getMessage()).contains("You cannot view users belonging to another tenant");
        verify(userRepository, never()).findByClientIdWithClient(any(), any());
    }

    // ==========================================
    // Tests for getUserById()
    // ==========================================

    @Test
    @DisplayName("getUserById - Should return mapped UserResponse when requesting user in own tenant")
    void getUserById_WhenSameTenant_ShouldReturnUserResponse() {
        // Arrange
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(mockUser));
        when(userRoleRepository.findByUserIdAndClientId(USER_ID, TENANT_CLIENT_ID))
                .thenReturn(List.of(mockUserRole));

        // Act
        UserResponse result = userService.getUserById(USER_ID, TENANT_CLIENT_ID.toString());

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.email()).isEqualTo(EMAIL);
        assertThat(result.roles()).containsExactly(ROLE_NAME);
    }

    @Test
    @DisplayName("getUserById - Should throw AccessDeniedException for cross-tenant ID guessing")
    void getUserById_WhenCrossTenant_ShouldThrowException() {
        // Arrange
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(mockUser));

        // Act & Assert
        AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> {
            // Attempting to fetch the user using a different tenant's token
            userService.getUserById(USER_ID, OTHER_TENANT_CLIENT_ID.toString());
        });

        assertThat(exception.getMessage()).contains("You do not have permission to view this user's details");
        verify(userRoleRepository, never()).findByUserIdAndClientId(any(), any());
    }

    @Test
    @DisplayName("getUserById - Should throw UserNotFoundException when user does not exist")
    void getUserById_WhenUserDoesNotExist_ShouldThrowException() {
        // Arrange
        when(userRepository.findById(USER_ID)).thenReturn(Optional.empty());

        // Act & Assert
        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> {
            userService.getUserById(USER_ID, TENANT_CLIENT_ID.toString());
        });

        assertThat(exception.getMessage()).isEqualTo("User not found");
        verify(userRoleRepository, never()).findByUserIdAndClientId(any(), any());
    }
}