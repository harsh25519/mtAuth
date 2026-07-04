package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.exceptionHandler.InvalidOAuthProviderException;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
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
class OAuth2ServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private UserRoleRepository userRoleRepository;
    @Mock private AuthService authService;

    @InjectMocks
    private OAuth2Service oAuth2Service;

    @Captor private ArgumentCaptor<User> userCaptor;
    @Captor private ArgumentCaptor<UserRole> roleCaptor;

    // --- Constants ---
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final UUID USER_ID = UUID.randomUUID();
    private static final String EMAIL = "oauth.user@example.com";
    private static final String PROVIDER_ID = "google-oauth-12345";
    private static final String ROLE_USER = "ROLE_USER";

    private Client mockClient;
    private OAuth2UserInfo mockUserInfo;
    private AuthResponse expectedTokens;
    private UserRole defaultRole;

    @BeforeEach
    void setUp() {
        mockClient = Client.builder().id(CLIENT_ID).build();

        // Assuming OAuth2UserInfo is a record
        mockUserInfo = new OAuth2UserInfo(EMAIL, PROVIDER_ID);
        expectedTokens = new AuthResponse("access-token", "refresh-token", "Bearer");

        defaultRole = UserRole.builder().role(ROLE_USER).build();
    }

    // ==========================================
    // Tests for processOAuthUser()
    // ==========================================

    @Test
    @DisplayName("processOAuthUser - Should create new user, assign role, and issue tokens when user does not exist")
    void processOAuthUser_WhenNewUser_ShouldCreateAndAuthenticate() {
        // Arrange
        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.empty());

        User newlySavedUser = User.builder()
                .id(USER_ID)
                .email(EMAIL)
                .authProvider(OAuthProvider.GOOGLE.name())
                .build();

        when(userRepository.save(any(User.class))).thenReturn(newlySavedUser);
        when(userRoleRepository.findByUserIdAndClientId(USER_ID, CLIENT_ID)).thenReturn(List.of(defaultRole));
        when(authService.issueTokens(USER_ID.toString(), CLIENT_ID.toString(), List.of(ROLE_USER))).thenReturn(expectedTokens);

        // Act
        AuthResponse result = oAuth2Service.processOAuthUser(mockClient, mockUserInfo, OAuthProvider.GOOGLE);

        // Assert
        assertThat(result).isEqualTo(expectedTokens);

        // 1. Verify User Creation Properties
        verify(userRepository).save(userCaptor.capture());
        User capturedUser = userCaptor.getValue();
        assertThat(capturedUser.getEmail()).isEqualTo(EMAIL);
        assertThat(capturedUser.getAuthProvider()).isEqualTo(OAuthProvider.GOOGLE.name());
        assertThat(capturedUser.getProviderId()).isEqualTo(PROVIDER_ID);
        assertThat(capturedUser.getIsActive()).isTrue();
        assertThat(capturedUser.getIsEmailVerified()).isTrue();

        // 2. Verify Default Role Assignment
        verify(userRoleRepository).save(roleCaptor.capture());
        UserRole capturedRole = roleCaptor.getValue();
        assertThat(capturedRole.getRole()).isEqualTo(ROLE_USER);
        assertThat(capturedRole.getClient()).isEqualTo(mockClient);
    }

    @Test
    @DisplayName("processOAuthUser - Should skip creation and issue tokens when user already exists with matching provider")
    void processOAuthUser_WhenExistingUser_ShouldAuthenticateDirectly() {
        // Arrange
        User existingUser = User.builder()
                .id(USER_ID)
                .email(EMAIL)
                .authProvider(OAuthProvider.GOOGLE.name())
                .build();

        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(existingUser));
        when(userRoleRepository.findByUserIdAndClientId(USER_ID, CLIENT_ID)).thenReturn(List.of(defaultRole));
        when(authService.issueTokens(USER_ID.toString(), CLIENT_ID.toString(), List.of(ROLE_USER))).thenReturn(expectedTokens);

        // Act
        AuthResponse result = oAuth2Service.processOAuthUser(mockClient, mockUserInfo, OAuthProvider.GOOGLE);

        // Assert
        assertThat(result).isEqualTo(expectedTokens);

        // Verify we did NOT attempt to create a new user or assign new roles
        verify(userRepository, never()).save(any());
        verify(userRoleRepository, never()).save(any());
    }

    @Test
    @DisplayName("processOAuthUser - Should throw InvalidOAuthProviderException when existing user used a different provider")
    void processOAuthUser_WhenProviderMismatch_ShouldThrowException() {
        // Arrange
        // User originally registered with GITHUB
        User existingUser = User.builder()
                .id(USER_ID)
                .email(EMAIL)
                .authProvider(OAuthProvider.GITHUB.name())
                .build();

        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(existingUser));

        // Act & Assert
        // User is now trying to log in with GOOGLE
        InvalidOAuthProviderException exception = assertThrows(InvalidOAuthProviderException.class, () -> {
            oAuth2Service.processOAuthUser(mockClient, mockUserInfo, OAuthProvider.GOOGLE);
        });

        assertThat(exception.getMessage()).isEqualTo("Account is registered using a different authentication provider.");

        // Security Check: Ensure tokens were never issued
        verify(authService, never()).issueTokens(anyString(), anyString(), anyList());
        verify(userRoleRepository, never()).findByUserIdAndClientId(any(), any());
    }
}