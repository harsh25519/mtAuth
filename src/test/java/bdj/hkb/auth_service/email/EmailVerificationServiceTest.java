package bdj.hkb.auth_service.email;

import bdj.hkb.auth_service.exceptionHandler.InvalidEmailVerificationTokenException;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import bdj.hkb.auth_service.user.emailVerification.EmailVerificationService;
import bdj.hkb.auth_service.user.emailVerification.EmailVerificationToken;
import bdj.hkb.auth_service.user.emailVerification.EmailVerificationTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailVerificationServiceTest {

    @Mock
    private EmailVerificationTokenRepository tokenRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private EmailVerificationService emailVerificationService;

    @Captor
    private ArgumentCaptor<EmailVerificationToken> tokenCaptor;

    // --- Constants ---
    private static final UUID USER_ID = UUID.randomUUID();
    private static final String VALID_TOKEN_STR = "secure-random-string-123";

    private User targetUser;
    private EmailVerificationToken validToken;
    private EmailVerificationToken expiredToken;

    @BeforeEach
    void setUp() {
        targetUser = User.builder()
                .id(USER_ID)
                .email("test@example.com")
                .isEmailVerified(false)
                .isActive(false)
                .build();

        validToken = EmailVerificationToken.builder()
                .token(VALID_TOKEN_STR)
                .user(targetUser)
                .expiresAt(OffsetDateTime.now().plusHours(2))
                .build();

        expiredToken = EmailVerificationToken.builder()
                .token(VALID_TOKEN_STR)
                .user(targetUser)
                .expiresAt(OffsetDateTime.now().minusHours(1))
                .build();
    }

    // ==========================================
    // Tests for createVerificationToken()
    // ==========================================

    @Test
    @DisplayName("createVerificationToken - Should wipe old tokens, save a new 24-hour token, and return it")
    void createVerificationToken_ShouldDeleteOldAndSaveNew() {
        // Act
        String generatedToken = emailVerificationService.createVerificationToken(targetUser);

        // Assert
        assertThat(generatedToken).isNotBlank();

        verify(tokenRepository).deleteByUser(targetUser);

        verify(tokenRepository).save(tokenCaptor.capture());
        EmailVerificationToken savedToken = tokenCaptor.getValue();

        assertThat(savedToken.getToken()).isEqualTo(generatedToken);
        assertThat(savedToken.getUser()).isEqualTo(targetUser);
        assertThat(savedToken.getExpiresAt()).isAfter(java.time.OffsetDateTime.now());
    }

    // ==========================================
    // Tests for verifyEmail()
    // ==========================================

    @Test
    @DisplayName("verifyEmail - Should unlock user account and burn the token when valid")
    void verifyEmail_WhenTokenIsValid_ShouldUpdateUserAndBurnToken() {
        // Arrange
        when(tokenRepository.findByToken(VALID_TOKEN_STR)).thenReturn(Optional.of(validToken));

        // Act
        emailVerificationService.verifyEmail(VALID_TOKEN_STR);

        // Assert
        assertThat(targetUser.getIsEmailVerified()).isTrue();
        assertThat(targetUser.getIsActive()).isTrue();

        verify(userRepository).save(targetUser);
        verify(tokenRepository).delete(validToken);
    }

    @Test
    @DisplayName("verifyEmail - Should throw InvalidEmailVerificationTokenException when token does not exist")
    void verifyEmail_WhenTokenNotFound_ShouldThrowException() {
        // Arrange
        when(tokenRepository.findByToken("fake-token")).thenReturn(Optional.empty());

        // Act & Assert
        InvalidEmailVerificationTokenException exception = assertThrows(InvalidEmailVerificationTokenException.class, () -> {
            emailVerificationService.verifyEmail("fake-token");
        });

        assertThat(exception.getMessage()).isEqualTo("Invalid verification token");

        verify(userRepository, never()).save(any());
        verify(tokenRepository, never()).delete(any());
    }

    @Test
    @DisplayName("verifyEmail - Should delete the token and throw Exception when expired")
    void verifyEmail_WhenTokenExpired_ShouldThrowExceptionAndCleanUp() {
        // Arrange
        when(tokenRepository.findByToken(VALID_TOKEN_STR)).thenReturn(Optional.of(expiredToken));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            emailVerificationService.verifyEmail(VALID_TOKEN_STR);
        });

        assertThat(exception.getMessage()).isEqualTo("Verification token has expired. Please request a new one.");

        assertThat(targetUser.getIsEmailVerified()).isFalse();
        verify(userRepository, never()).save(any());

        verify(tokenRepository).delete(expiredToken);
    }
}