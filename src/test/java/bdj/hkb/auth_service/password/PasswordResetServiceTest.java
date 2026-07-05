package bdj.hkb.auth_service.password;

import bdj.hkb.auth_service.exceptionHandler.InvalidPasswordResetTokenException;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import bdj.hkb.auth_service.user.passwordReset.PasswordResetService;
import bdj.hkb.auth_service.user.passwordReset.PasswordResetToken;
import bdj.hkb.auth_service.user.passwordReset.PasswordResetTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private PasswordResetTokenRepository tokenRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private PasswordResetService passwordResetService;

    @Captor
    private ArgumentCaptor<PasswordResetToken> tokenCaptor;

    // --- Constants ---
    private static final UUID USER_ID = UUID.randomUUID();
    private static final String VALID_TOKEN_STR = "reset-secure-string-999";
    private static final String NEW_RAW_PASSWORD = "MyNewSuperSecretPassword123!";
    private static final String MOCKED_HASH = "$2a$10$mockedBcryptHashValue...";

    private User targetUser;
    private PasswordResetToken validToken;
    private PasswordResetToken expiredToken;

    @BeforeEach
    void setUp() {
        targetUser = User.builder()
                .id(USER_ID)
                .email("test@example.com")
                .passwordHash("oldHashValue")
                .isActive(true)
                .build();

        validToken = PasswordResetToken.builder()
                .token(VALID_TOKEN_STR)
                .user(targetUser)
                .expiresAt(OffsetDateTime.now().plusMinutes(10))
                .build();

        expiredToken = PasswordResetToken.builder()
                .token(VALID_TOKEN_STR)
                .user(targetUser)
                .expiresAt(OffsetDateTime.now().minusMinutes(5))
                .build();
    }

    // ==========================================
    // Tests for createResetToken()
    // ==========================================

    @Test
    @DisplayName("createResetToken - Should wipe old tokens, save a new 15-minute token, and return it")
    void createResetToken_ShouldDeleteOldAndSaveNew() {
        // Act
        String generatedToken = passwordResetService.createResetToken(targetUser);

        // Assert
        assertThat(generatedToken).isNotBlank();

        verify(tokenRepository).deleteByUser(targetUser);

        verify(tokenRepository).save(tokenCaptor.capture());
        PasswordResetToken savedToken = tokenCaptor.getValue();

        assertThat(savedToken.getToken()).isEqualTo(generatedToken);
        assertThat(savedToken.getUser()).isEqualTo(targetUser);
        assertThat(savedToken.getExpiresAt()).isAfter(OffsetDateTime.now());
    }

    // ==========================================
    // Tests for executePasswordReset()
    // ==========================================

    @Test
    @DisplayName("executePasswordReset - Should hash new password, save user, and burn token when valid")
    void executePasswordReset_WhenTokenIsValid_ShouldUpdateUserAndBurnToken() {
        // Arrange
        when(tokenRepository.findByToken(VALID_TOKEN_STR)).thenReturn(Optional.of(validToken));
        when(passwordEncoder.encode(NEW_RAW_PASSWORD)).thenReturn(MOCKED_HASH);

        // Act
        passwordResetService.executePasswordReset(VALID_TOKEN_STR, NEW_RAW_PASSWORD);

        // Assert
        assertThat(targetUser.getPasswordHash()).isEqualTo(MOCKED_HASH);

        verify(passwordEncoder).encode(NEW_RAW_PASSWORD);
        verify(userRepository).save(targetUser);
        verify(tokenRepository).delete(validToken);
    }

    @Test
    @DisplayName("executePasswordReset - Should throw InvalidPasswordResetTokenException when token does not exist")
    void executePasswordReset_WhenTokenNotFound_ShouldThrowException() {
        // Arrange
        when(tokenRepository.findByToken("fake-token")).thenReturn(Optional.empty());

        // Act & Assert
        InvalidPasswordResetTokenException exception = assertThrows(InvalidPasswordResetTokenException.class, () -> {
            passwordResetService.executePasswordReset("fake-token", NEW_RAW_PASSWORD);
        });

        assertThat(exception.getMessage()).isEqualTo("Invalid password reset token");

        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any());
        verify(tokenRepository, never()).delete(any());
    }

    @Test
    @DisplayName("executePasswordReset - Should delete the token and throw Exception when expired")
    void executePasswordReset_WhenTokenExpired_ShouldThrowExceptionAndCleanUp() {
        // Arrange
        when(tokenRepository.findByToken(VALID_TOKEN_STR)).thenReturn(Optional.of(expiredToken));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            passwordResetService.executePasswordReset(VALID_TOKEN_STR, NEW_RAW_PASSWORD);
        });

        assertThat(exception.getMessage()).isEqualTo("Reset token has expired. Please request a new one.");

        assertThat(targetUser.getPasswordHash()).isEqualTo("oldHashValue");
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any());

        verify(tokenRepository).delete(expiredToken);
    }
}