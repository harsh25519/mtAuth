package bdj.hkb.auth_service.user;

import bdj.hkb.auth_service.client.Client;
import jakarta.persistence.PersistenceUnitUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    private Client savedClient1;
    private Client savedClient2;
    private User savedUser1;

    @BeforeEach
    void setUp() {
        // 1. Setup Clients
        Client client1 = Client.builder()
                .name("Test Client 1")
                .clientSecret("secret1")
                .redirectUrl("http://localhost:8080/cb1")
                .build();

        Client client2 = Client.builder()
                .name("Test Client 2")
                .clientSecret("secret2")
                .redirectUrl("http://localhost:8080/cb2")
                .build();

        savedClient1 = entityManager.persistAndFlush(client1);
        savedClient2 = entityManager.persistAndFlush(client2);

        // 2. Setup User
        User user1 = User.builder()
                .client(savedClient1)
                .email("alice@example.com")
                .passwordHash("hashedpassword123")
                .authProvider("GOOGLE")
                .providerId("google-123")
                .build();

        savedUser1 = entityManager.persistAndFlush(user1);
    }

    @Test
    @DisplayName("Should find user by Client ID and Email")
    void findByClientIdAndEmail_WhenExists_ShouldReturnUser() {
        Optional<User> found = userRepository.findByClientIdAndEmail(savedClient1.getId(), "alice@example.com");

        assertThat(found).isPresent();
        assertThat(found.get().getId()).isEqualTo(savedUser1.getId());
    }

    @Test
    @DisplayName("Should return empty when searching by wrong Client ID but correct Email")
    void findByClientIdAndEmail_WhenWrongClientId_ShouldReturnEmpty() {
        Optional<User> found = userRepository.findByClientIdAndEmail(savedClient2.getId(), "alice@example.com");

        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("Should return true if user exists by Client ID and Email")
    void existsByClientIdAndEmail_WhenExists_ShouldReturnTrue() {
        boolean exists = userRepository.existsByClientIdAndEmail(savedClient1.getId(), "alice@example.com");

        assertThat(exists).isTrue();
    }

    @Test
    @DisplayName("Should find user by Provider ID and Auth Provider")
    void findByProviderIdAndAuthProvider_WhenExists_ShouldReturnUser() {
        Optional<User> found = userRepository.findByProviderIdAndAuthProvider("google-123", "GOOGLE");

        assertThat(found).isPresent();
        assertThat(found.get().getEmail()).isEqualTo("alice@example.com");
    }

    @Test
    @DisplayName("Should fetch all users with clients using EntityGraph and Pagination")
    void findAllWithClient_ShouldReturnPagedUsers() {
        // Arrange: Add a second user
        User user2 = User.builder()
                .client(savedClient2)
                .email("bob@example.com")
                .authProvider("GITHUB")
                .providerId("github-456")
                .build();
        entityManager.persistAndFlush(user2);

        Pageable pageable = PageRequest.of(0, 10);

        // Act
        Page<User> usersPage = userRepository.findAllWithClient(pageable);

        // Assert
        assertThat(usersPage.getTotalElements()).isEqualTo(2);
        PersistenceUnitUtil util =
                entityManager.getEntityManager()
                        .getEntityManagerFactory()
                        .getPersistenceUnitUtil();

        assertThat(
                util.isLoaded(usersPage.getContent().get(0).getClient())
        ).isTrue();
    }

    @Test
    @DisplayName("Should fetch users for a specific client using EntityGraph and Pagination")
    void findByClientIdWithClient_ShouldReturnPagedUsersForClient() {
        // Arrange: Add another user to Client 1, and one to Client 2
        User user2 = User.builder()
                .client(savedClient1)
                .email("charlie@example.com")
                .authProvider("LOCAL")
                .build();

        User user3 = User.builder()
                .client(savedClient2)
                .email("dave@example.com")
                .authProvider("LOCAL")
                .build();

        entityManager.persistAndFlush(user2);
        entityManager.persistAndFlush(user3);

        Pageable pageable = PageRequest.of(0, 10);

        // Act
        Page<User> client1Users = userRepository.findByClientIdWithClient(savedClient1.getId(), pageable);

        // Assert
        assertThat(client1Users.getTotalElements()).isEqualTo(2); // Alice and Charlie
        assertThat(client1Users.getContent()).extracting("email")
                .containsExactlyInAnyOrder("alice@example.com", "charlie@example.com");
    }

    @Test
    @DisplayName("Should find user by ID and Client ID")
    void findByIdAndClientId_WhenMatches_ShouldReturnUser() {
        Optional<User> found = userRepository.findByIdAndClientId(savedUser1.getId(), savedClient1.getId());

        assertThat(found).isPresent();
        assertThat(found.get().getEmail()).isEqualTo("alice@example.com");
    }

    @Test
    @DisplayName("Should return empty when finding user by ID but wrong Client ID")
    void findByIdAndClientId_WhenWrongClientId_ShouldReturnEmpty() {
        Optional<User> found = userRepository.findByIdAndClientId(savedUser1.getId(), savedClient2.getId());

        assertThat(found).isEmpty();
    }
}
