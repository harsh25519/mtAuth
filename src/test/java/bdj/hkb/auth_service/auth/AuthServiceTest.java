package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.LocalLoginRequest;
import bdj.hkb.auth_service.auth.dto.LocalSignupRequest;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.exceptionHandler.*;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.security.RefreshTokenService;
import bdj.hkb.auth_service.security.TokenBlacklistService;
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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private ClientRepository clientRepository;
    @Mock
    private UserRoleRepository userRoleRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtUtilService jwtUtil;
    @Mock
    private TokenBlacklistService tokenBlacklistService;
    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private AuthService authService;

    @Captor
    private ArgumentCaptor<User> userCaptor;
    @Captor
    private ArgumentCaptor<UserRole> roleCaptor;

    // --- Constants ---
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final UUID USER_ID = UUID.randomUUID();
    private static final String EMAIL = "test@example.com";
    private static final String RAW_PASSWORD = "Password123!";
    private static final String ENCODED_PASSWORD = "encodedPassword";
    private static final String RAW_SECRET = "clientSecret";
    private static final String ENCODED_SECRET = "encodedSecret";

    private static final String ACCESS_TOKEN = "mock.access.token";
    private static final String REFRESH_TOKEN = "mock.refresh.token";
    private static final String JTI = UUID.randomUUID().toString();

    private Client mockClient;
    private User mockUser;

    @BeforeEach
    void setUp() {
        mockClient = Client.builder()
                .id(CLIENT_ID)
                .clientSecret(ENCODED_SECRET)
                .isActive(true)
                .build();

        mockUser = User.builder()
                .id(USER_ID)
                .client(mockClient)
                .email(EMAIL)
                .passwordHash(ENCODED_PASSWORD)
                .authProvider("local")
                .isActive(true)
                .isEmailVerified(true)
                .build();
    }

    // ==========================================
    // Tests for registerLocalUser()
    // ==========================================

    @Test
    @DisplayName("registerLocalUser - Should successfully register user and assign default role")
    void registerLocalUser_WhenValid_ShouldSaveUserAndRole() {
        // Arrange
        LocalSignupRequest request = new LocalSignupRequest(EMAIL, RAW_PASSWORD, CLIENT_ID, RAW_SECRET);

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(passwordEncoder.matches(RAW_SECRET, ENCODED_SECRET)).thenReturn(true);
        when(userRepository.existsByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(ENCODED_PASSWORD);
        when(userRepository.save(any(User.class))).thenReturn(mockUser);

        // Act
        User result = authService.registerLocalUser(request);

        // Assert
        assertThat(result).isEqualTo(mockUser);

        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        assertThat(savedUser.getEmail()).isEqualTo(EMAIL);
        assertThat(savedUser.getPasswordHash()).isEqualTo(ENCODED_PASSWORD);
        assertThat(savedUser.getIsActive()).isFalse(); // Defaults for new registration

        verify(userRoleRepository).save(roleCaptor.capture());
        UserRole savedRole = roleCaptor.getValue();
        assertThat(savedRole.getRole()).isEqualTo("ROLE_USER");
    }

    @Test
    @DisplayName("registerLocalUser - Should throw InvalidClientSecretException when secrets mismatch")
    void registerLocalUser_WhenSecretMismatch_ShouldThrowException() {
        // Arrange
        LocalSignupRequest request = new LocalSignupRequest(EMAIL, RAW_PASSWORD, CLIENT_ID, "wrong-secret");

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(passwordEncoder.matches("wrong-secret", ENCODED_SECRET)).thenReturn(false);

        // Act & Assert
        assertThrows(InvalidClientSecretException.class, () -> authService.registerLocalUser(request));
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("registerLocalUser - Should handle DataIntegrityViolationException and map to UserAlreadyExistsException")
    void registerLocalUser_WhenDatabaseThrowsConstraintViolation_ShouldMapException() {
        // Arrange
        LocalSignupRequest request = new LocalSignupRequest(EMAIL, RAW_PASSWORD, CLIENT_ID, RAW_SECRET);

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(passwordEncoder.matches(RAW_SECRET, ENCODED_SECRET)).thenReturn(true);
        when(userRepository.existsByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(false);
        when(passwordEncoder.encode(RAW_PASSWORD)).thenReturn(ENCODED_PASSWORD);

        when(userRepository.save(any(User.class))).thenThrow(new DataIntegrityViolationException("Duplicate"));

        // Act & Assert
        assertThrows(UserAlreadyExistsException.class, () -> authService.registerLocalUser(request));
        verify(userRoleRepository, never()).save(any());
    }

    // ==========================================
    // Tests for authenticateLocalUser()
    // ==========================================

    @Test
    @DisplayName("authenticateLocalUser - Should authenticate and return tokens when credentials are valid")
    void authenticateLocalUser_WhenValid_ShouldIssueTokens() {
        // Arrange
        LocalLoginRequest request = new LocalLoginRequest(EMAIL, RAW_PASSWORD, CLIENT_ID);
        UserRole userRole = UserRole.builder().role("ROLE_USER").build();

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(mockUser));
        when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
        when(userRoleRepository.findByUserIdAndClientId(USER_ID, CLIENT_ID)).thenReturn(List.of(userRole));

        when(jwtUtil.generateAccessToken(eq(USER_ID.toString()), eq(CLIENT_ID.toString()), anyList())).thenReturn(ACCESS_TOKEN);
        when(jwtUtil.generateRefreshToken(USER_ID.toString(), CLIENT_ID.toString())).thenReturn(REFRESH_TOKEN);
        when(jwtUtil.extractJti(REFRESH_TOKEN)).thenReturn(JTI);
        when(jwtUtil.extractExpiration(REFRESH_TOKEN)).thenReturn(new Date(System.currentTimeMillis() + 100000));

        // Act
        AuthResponse response = authService.authenticateLocalUser(request);

        // Assert
        assertThat(response.accessToken()).isEqualTo(ACCESS_TOKEN);
        assertThat(response.refreshToken()).isEqualTo(REFRESH_TOKEN);
        verify(refreshTokenService).store(eq(USER_ID.toString()), eq(CLIENT_ID.toString()), eq(JTI), anyLong());
    }

    @Test
    @DisplayName("authenticateLocalUser - Should throw exception if auth provider is not 'local'")
    void authenticateLocalUser_WhenProviderIsOAuth_ShouldThrowException() {
        // Arrange
        mockUser.setAuthProvider("GOOGLE");
        LocalLoginRequest request = new LocalLoginRequest(EMAIL, RAW_PASSWORD, CLIENT_ID);

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(mockUser));

        // Act & Assert
        InvalidCredentialsException exception = assertThrows(InvalidCredentialsException.class, () -> authService.authenticateLocalUser(request));
        assertThat(exception.getMessage()).contains("Wrong auth provider");
    }

    @Test
    @DisplayName("authenticateLocalUser - Should throw exception if email is not verified")
    void authenticateLocalUser_WhenEmailNotVerified_ShouldThrowException() {
        // Arrange
        mockUser.setIsEmailVerified(false);
        LocalLoginRequest request = new LocalLoginRequest(EMAIL, RAW_PASSWORD, CLIENT_ID);

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(mockUser));
        when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);

        // Act & Assert
        assertThrows(EmailNotVerifiedException.class, () -> authService.authenticateLocalUser(request));
    }

    // ==========================================
    // Tests for logout()
    // ==========================================

    @Test
    @DisplayName("logout - Should extract claims, blacklist access token, and revoke refresh token")
    void logout_ShouldBlacklistAndRevoke() {
        // Arrange
        long expirationTime = System.currentTimeMillis() + 50000;
        when(jwtUtil.extractJti(ACCESS_TOKEN)).thenReturn(JTI);
        when(jwtUtil.extractUserId(ACCESS_TOKEN)).thenReturn(USER_ID.toString());
        when(jwtUtil.extractClientId(ACCESS_TOKEN)).thenReturn(CLIENT_ID.toString());
        when(jwtUtil.extractExpiration(ACCESS_TOKEN)).thenReturn(new Date(expirationTime));

        // Act
        authService.logout(ACCESS_TOKEN);

        // Assert
        verify(tokenBlacklistService).blacklist(eq(JTI), anyLong());
        verify(refreshTokenService).revoke(USER_ID.toString(), CLIENT_ID.toString());
    }

    // ==========================================
    // Tests for refreshAccessToken()
    // ==========================================

    @Test
    @DisplayName("refreshAccessToken - Should issue new tokens if refresh token is valid")
    void refreshAccessToken_WhenValid_ShouldIssueNewTokens() {
        // Arrange
        UserRole userRole = UserRole.builder().role("ROLE_USER").build();

        when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);
        when(jwtUtil.extractTokenType(REFRESH_TOKEN)).thenReturn("refresh");
        when(jwtUtil.extractUserId(REFRESH_TOKEN)).thenReturn(USER_ID.toString());
        when(jwtUtil.extractJti(REFRESH_TOKEN)).thenReturn(JTI);
        when(jwtUtil.extractClientId(REFRESH_TOKEN)).thenReturn(CLIENT_ID.toString());

        when(refreshTokenService.isValid(USER_ID.toString(), CLIENT_ID.toString(), JTI)).thenReturn(true);
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(mockUser));
        when(userRoleRepository.findByUserIdAndClientId(USER_ID, CLIENT_ID)).thenReturn(List.of(userRole));

        when(jwtUtil.generateAccessToken(eq(USER_ID.toString()), eq(CLIENT_ID.toString()), anyList())).thenReturn("new-access-token");
        when(jwtUtil.generateRefreshToken(USER_ID.toString(), CLIENT_ID.toString())).thenReturn("new-refresh-token");
        when(jwtUtil.extractJti("new-refresh-token")).thenReturn("new-jti");
        when(jwtUtil.extractExpiration("new-refresh-token")).thenReturn(new Date(System.currentTimeMillis() + 100000));

        // Act
        AuthResponse response = authService.refreshAccessToken(REFRESH_TOKEN);

        // Assert
        assertThat(response.accessToken()).isEqualTo("new-access-token");
        verify(refreshTokenService).store(eq(USER_ID.toString()), eq(CLIENT_ID.toString()), eq("new-jti"), anyLong());
    }

    @Test
    @DisplayName("refreshAccessToken - Should throw InvalidTokenException if token type is not 'refresh'")
    void refreshAccessToken_WhenWrongTokenType_ShouldThrowException() {
        // Arrange
        when(jwtUtil.validateToken(ACCESS_TOKEN)).thenReturn(true);
        when(jwtUtil.extractTokenType(ACCESS_TOKEN)).thenReturn("access");

        // Act & Assert
        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () -> authService.refreshAccessToken(ACCESS_TOKEN));
        assertThat(exception.getMessage()).contains("Token is not a refresh token");

        verify(refreshTokenService, never()).isValid(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("refreshAccessToken - Should throw InvalidTokenException if token is revoked in Redis")
    void refreshAccessToken_WhenRevokedInRedis_ShouldThrowException() {
        // Arrange
        when(jwtUtil.validateToken(REFRESH_TOKEN)).thenReturn(true);
        when(jwtUtil.extractTokenType(REFRESH_TOKEN)).thenReturn("refresh");
        when(jwtUtil.extractUserId(REFRESH_TOKEN)).thenReturn(USER_ID.toString());
        when(jwtUtil.extractJti(REFRESH_TOKEN)).thenReturn(JTI);
        when(jwtUtil.extractClientId(REFRESH_TOKEN)).thenReturn(CLIENT_ID.toString());

        when(refreshTokenService.isValid(USER_ID.toString(), CLIENT_ID.toString(), JTI)).thenReturn(false);

        // Act & Assert
        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () -> authService.refreshAccessToken(REFRESH_TOKEN));
        assertThat(exception.getMessage()).contains("revoked or replaced");

        verify(userRepository, never()).findById(any());
    }
}
