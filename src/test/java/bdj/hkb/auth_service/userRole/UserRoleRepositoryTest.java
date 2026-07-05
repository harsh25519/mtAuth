package bdj.hkb.auth_service.userRole;

import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.user.User;
import jakarta.persistence.PersistenceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DataJpaTest
class UserRoleRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRoleRepository userRoleRepository;

    // --- Constants ---
    private static final String ROLE_USER = "ROLE_USER";
    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String EMAIL_1 = "user1@example.com";
    private static final String EMAIL_2 = "user2@example.com";

    private Client savedClient;
    private Client otherClient;
    private User savedUser1;
    private User savedUser2;

    @BeforeEach
    void setUp() {
        // 1. Setup Clients
        Client client1 = Client.builder()
                .name("Primary App")
                .clientSecret("secret1")
                .redirectUrl("http://localhost/cb1")
                .build();

        Client client2 = Client.builder()
                .name("Secondary App")
                .clientSecret("secret2")
                .redirectUrl("http://localhost/cb2")
                .build();

        savedClient = entityManager.persistAndFlush(client1);
        otherClient = entityManager.persistAndFlush(client2);

        // 2. Setup Users
        User user1 = User.builder()
                .client(savedClient)
                .email(EMAIL_1)
                .authProvider("LOCAL")
                .build();

        User user2 = User.builder()
                .client(savedClient)
                .email(EMAIL_2)
                .authProvider("LOCAL")
                .build();

        savedUser1 = entityManager.persistAndFlush(user1);
        savedUser2 = entityManager.persistAndFlush(user2);

        // 3. Setup Roles
        UserRole role1 = UserRole.builder()
                .user(savedUser1)
                .client(savedClient)
                .role(ROLE_USER)
                .build();

        UserRole role2 = UserRole.builder()
                .user(savedUser1)
                .client(savedClient)
                .role(ROLE_ADMIN)
                .build();

        UserRole role3 = UserRole.builder()
                .user(savedUser2)
                .client(savedClient)
                .role(ROLE_USER)
                .build();

        entityManager.persistAndFlush(role1);
        entityManager.persistAndFlush(role2);
        entityManager.persistAndFlush(role3);
    }

    @Test
    @DisplayName("Should return roles when finding by correct User ID and Client ID")
    void findByUserIdAndClientId_WhenExists_ShouldReturnRoles() {
        // Act
        List<UserRole> roles = userRoleRepository.findByUserIdAndClientId(savedUser1.getId(), savedClient.getId());

        // Assert
        assertThat(roles).hasSize(2);
        assertThat(roles).extracting("role")
                .containsExactlyInAnyOrder(ROLE_USER, ROLE_ADMIN);
    }

    @Test
    @DisplayName("Should return empty list when searching by correct User ID but wrong Client ID")
    void findByUserIdAndClientId_WhenWrongClientId_ShouldReturnEmpty() {
        // Act
        List<UserRole> roles = userRoleRepository.findByUserIdAndClientId(savedUser1.getId(), otherClient.getId());

        // Assert
        assertThat(roles).isEmpty();
    }

    @Test
    @DisplayName("Should return empty list when searching by wrong User ID")
    void findByUserIdAndClientId_WhenWrongUserId_ShouldReturnEmpty() {
        // Arrange
        UUID fakeUserId = UUID.randomUUID();

        // Act
        List<UserRole> roles = userRoleRepository.findByUserIdAndClientId(fakeUserId, savedClient.getId());

        // Assert
        assertThat(roles).isEmpty();
    }

    @Test
    @DisplayName("Should return roles for multiple users using an IN clause")
    void findByUserIds_WhenUsersExist_ShouldReturnAllMatchingRoles() {
        // Arrange
        List<UUID> userIds = List.of(savedUser1.getId(), savedUser2.getId());

        // Act
        List<UserRole> roles = userRoleRepository.findByUserIds(userIds);

        // Assert
        assertThat(roles).hasSize(3); // 2 roles for user1, 1 role for user2
        assertThat(roles).extracting("user.email")
                .contains(EMAIL_1, EMAIL_1, EMAIL_2);
    }

    @Test
    @DisplayName("Should return empty list when passing empty list to IN clause")
    void findByUserIds_WhenListIsEmpty_ShouldReturnEmpty() {
        // Act
        List<UserRole> roles = userRoleRepository.findByUserIds(Collections.emptyList());

        // Assert
        assertThat(roles).isEmpty();
    }

    @Test
    @DisplayName("Should throw exception when saving role without a required 'role' string")
    void save_WhenRoleStringIsNull_ShouldThrowException() {
        // Arrange
        UserRole invalidRole = UserRole.builder()
                .user(savedUser1)
                .client(savedClient)
                .build();

        // Act & Assert
        assertThrows(PersistenceException.class, () -> {
            entityManager.persistAndFlush(invalidRole);
        });
    }
}
