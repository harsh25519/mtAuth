package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.LocalSignupRequest;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import bdj.hkb.auth_service.user.emailVerification.EmailVerificationService;
import bdj.hkb.auth_service.user.emailVerification.dto.ResendVerificationRequest;
import bdj.hkb.auth_service.user.passwordReset.PasswordResetService;
import bdj.hkb.auth_service.user.passwordReset.dto.ForgotPasswordRequest;
import bdj.hkb.auth_service.utils.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LocalAuthOrchestratorTest {

    @Mock
    private ClientRepository clientRepository;
    @Mock
    private AuthService authService;
    @Mock
    private EmailVerificationService emailVerificationService;
    @Mock
    private EmailService emailService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordResetService passwordResetService;

    @InjectMocks
    private LocalAuthOrchestrator orchestrator;

    // --- Constants ---
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final UUID USER_ID = UUID.randomUUID();
    private static final String EMAIL = "user@example.com";
    private static final String MOCK_TOKEN = "mock-secure-token-123";

    private Client mockClient;
    private User mockUser;

    @BeforeEach
    void setUp() {
        mockClient = Client.builder().id(CLIENT_ID).isActive(true).build();

        mockUser = User.builder()
                .id(USER_ID)
                .email(EMAIL)
                .client(mockClient)
                .authProvider("local")
                .isEmailVerified(false)
                .build();
    }

    // ==========================================
    // Tests for registerUserAndDispatchEmail()
    // ==========================================

    @Test
    @DisplayName("registerUserAndDispatchEmail - Should orchestrate signup and email dispatch successfully")
    void registerUserAndDispatchEmail_WhenValidRequest_ShouldSucceed() {
        // Arrange
        LocalSignupRequest request = new LocalSignupRequest(EMAIL, "password", CLIENT_ID, "secret");

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(authService.registerLocalUser(request)).thenReturn(mockUser);
        when(emailVerificationService.createVerificationToken(mockUser)).thenReturn(MOCK_TOKEN);

        // Act
        orchestrator.registerUserAndDispatchEmail(request);

        // Assert
        verify(authService).registerLocalUser(request);
        verify(emailVerificationService).createVerificationToken(mockUser);
        verify(emailService).sendVerificationEmail(EMAIL, MOCK_TOKEN);
    }

    @Test
    @DisplayName("registerUserAndDispatchEmail - Should throw Exception if Client is invalid")
    void registerUserAndDispatchEmail_WhenInvalidClient_ShouldThrowException() {
        // Arrange
        LocalSignupRequest request = new LocalSignupRequest(EMAIL, "password", CLIENT_ID, "secret");
        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            orchestrator.registerUserAndDispatchEmail(request);
        });
        assertThat(exception.getMessage()).isEqualTo("Invalid Client ID");

        // Verify downstream services are NEVER called
        verify(authService, never()).registerLocalUser(any());
        verify(emailService, never()).sendVerificationEmail(any(), any());
    }

    // ==========================================
    // Tests for resendVerificationEmail()
    // ==========================================

    @Test
    @DisplayName("resendVerificationEmail - Should generate new token and dispatch email")
    void resendVerificationEmail_WhenValid_ShouldSucceed() {
        // Arrange
        ResendVerificationRequest request = new ResendVerificationRequest(EMAIL, CLIENT_ID);

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(mockUser));
        when(emailVerificationService.createVerificationToken(mockUser)).thenReturn(MOCK_TOKEN);

        // Act
        orchestrator.resendVerificationEmail(request);

        // Assert
        verify(emailVerificationService).createVerificationToken(mockUser);
        verify(emailService).sendVerificationEmail(EMAIL, MOCK_TOKEN);
    }

    @Test
    @DisplayName("resendVerificationEmail - Should prevent spam if email is already verified")
    void resendVerificationEmail_WhenAlreadyVerified_ShouldThrowException() {
        // Arrange
        mockUser.setIsEmailVerified(true); // User is already verified
        ResendVerificationRequest request = new ResendVerificationRequest(EMAIL, CLIENT_ID);

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(mockUser));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            orchestrator.resendVerificationEmail(request);
        });
        assertThat(exception.getMessage()).isEqualTo("Email is already verified. Please log in.");

        verify(emailVerificationService, never()).createVerificationToken(any());
    }

    // ==========================================
    // Tests for requestPasswordReset()
    // ==========================================

    @Test
    @DisplayName("requestPasswordReset - Should orchestrate reset token creation and email dispatch")
    void requestPasswordReset_WhenLocalUser_ShouldSucceed() {
        // Arrange
        ForgotPasswordRequest request = new ForgotPasswordRequest(EMAIL, CLIENT_ID);

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(mockUser));
        when(passwordResetService.createResetToken(mockUser)).thenReturn(MOCK_TOKEN);

        // Act
        orchestrator.requestPasswordReset(request);

        // Assert
        verify(passwordResetService).createResetToken(mockUser);
        verify(emailService).sendPasswordResetEmail(EMAIL, MOCK_TOKEN);
    }

    @Test
    @DisplayName("requestPasswordReset - Should silently do nothing if user is OAuth (not local)")
    void requestPasswordReset_WhenOAuthUser_ShouldNotSendEmail() {
        // Arrange
        mockUser.setAuthProvider("GOOGLE"); // Not a local user
        ForgotPasswordRequest request = new ForgotPasswordRequest(EMAIL, CLIENT_ID);

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(userRepository.findByClientIdAndEmail(CLIENT_ID, EMAIL)).thenReturn(Optional.of(mockUser));

        // Act
        orchestrator.requestPasswordReset(request);

        // Assert
        verify(passwordResetService, never()).createResetToken(any());
        verify(emailService, never()).sendPasswordResetEmail(any(), any());
    }
}
