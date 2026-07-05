package bdj.hkb.auth_service.password;

import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.passwordReset.PasswordResetToken;
import bdj.hkb.auth_service.user.passwordReset.PasswordResetTokenRepository;
import jakarta.persistence.PersistenceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;

import java.time.OffsetDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DataJpaTest
class PasswordResetTokenRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    // --- Constants for Test Data ---
    private static final String VALID_TOKEN = "reset-me-98765";
    private static final String UNKNOWN_TOKEN = "invalid-token-111";
    private static final String USER_EMAIL_1 = "diana@example.com";
    private static final String USER_EMAIL_2 = "edward@example.com";

    private User userWithToken;
    private User userWithoutToken;
    private PasswordResetToken savedToken;

    @BeforeEach
    void setUp() {
        // Arrange: Setup Client -> User -> Token hierarchy
        Client client = Client.builder()
                .name("Password App")
                .clientSecret("secret-pass")
                .redirectUrl("http://localhost/cb-pass")
                .build();
        client = entityManager.persistAndFlush(client);

        User user1 = User.builder()
                .client(client)
                .email(USER_EMAIL_1)
                .authProvider("LOCAL")
                .build();
        userWithToken = entityManager.persistAndFlush(user1);

        User user2 = User.builder()
                .client(client)
                .email(USER_EMAIL_2)
                .authProvider("LOCAL")
                .build();
        userWithoutToken = entityManager.persistAndFlush(user2);

        PasswordResetToken token = PasswordResetToken.builder()
                .token(VALID_TOKEN)
                .user(userWithToken)
                .expiresAt(OffsetDateTime.now().plusHours(1))
                .build();
        savedToken = entityManager.persistAndFlush(token);
    }

    @Test
    @DisplayName("Should find token entity by its exact string value")
    void findByToken_WhenExists_ShouldReturnToken() {
        // Act
        Optional<PasswordResetToken> found = tokenRepository.findByToken(VALID_TOKEN);

        // Assert
        assertThat(found).isPresent();
        assertThat(found.get().getUser().getEmail()).isEqualTo(USER_EMAIL_1);
    }

    @Test
    @DisplayName("Should return empty when searching by a non-existent token string")
    void findByToken_WhenDoesNotExist_ShouldReturnEmpty() {
        // Act
        Optional<PasswordResetToken> found = tokenRepository.findByToken(UNKNOWN_TOKEN);

        // Assert
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("Should delete the token associated with a specific User")
    void deleteByUser_WhenUserHasToken_ShouldRemoveToken() {
        // Act
        tokenRepository.deleteByUser(userWithToken);

        // Flush the delete to the DB so we can verify it's gone
        entityManager.flush();
        entityManager.clear();

        // Assert
        Optional<PasswordResetToken> checkToken = tokenRepository.findByToken(VALID_TOKEN);
        assertThat(checkToken).isEmpty();

        User checkUser = entityManager.find(User.class, userWithToken.getId());
        assertThat(checkUser).isNotNull();
    }

    @Test
    @DisplayName("Should throw exception when trying to save a token string that already exists (Unique Constraint)")
    void save_WhenTokenStringAlreadyExists_ShouldThrowException() {
        // Arrange
        PasswordResetToken duplicateToken = PasswordResetToken.builder()
                .token(VALID_TOKEN) // Attempting to reuse the same string
                .user(userWithoutToken) // Different user, but same token string
                .expiresAt(OffsetDateTime.now().plusHours(1))
                .build();

        // Act & Assert
        assertThrows(PersistenceException.class, () -> {
            entityManager.persistAndFlush(duplicateToken);
        });
    }

    @Test
    @DisplayName("Should throw exception when saving without a required expiresAt timestamp (Nullable = false)")
    void save_WhenExpiresAtIsMissing_ShouldThrowException() {
        // Arrange
        PasswordResetToken invalidToken = PasswordResetToken.builder()
                .token("some-new-token-string")
                .user(userWithoutToken)
                // .expiresAt(...) intentionally omitted
                .build();

        // Act & Assert
        assertThrows(PersistenceException.class, () -> {
            entityManager.persistAndFlush(invalidToken);
        });
    }

    @Test
    @DisplayName("Should throw exception when attempting to assign a second token to the same User (OneToOne Unique Constraint)")
    void save_WhenUserAlreadyHasToken_ShouldThrowException() {
        // Arrange
        PasswordResetToken secondTokenForSameUser = PasswordResetToken.builder()
                .token("a-completely-new-reset-token")
                .user(userWithToken) // This user already has a token attached
                .expiresAt(OffsetDateTime.now().plusHours(1))
                .build();

        // Act & Assert
        assertThrows(PersistenceException.class, () -> {
            entityManager.persistAndFlush(secondTokenForSameUser);
        });
    }
}
