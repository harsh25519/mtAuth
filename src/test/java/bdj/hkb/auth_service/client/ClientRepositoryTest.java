package bdj.hkb.auth_service.client;

import jakarta.persistence.PersistenceException;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DataJpaTest
class ClientRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private ClientRepository clientRepository;

    // --- Constants ---
    private static final String ACTIVE_CLIENT_NAME = "Active App";
    private static final String INACTIVE_CLIENT_NAME = "Legacy App";
    private static final String CLIENT_SECRET = "super-secret-key";
    private static final String REDIRECT_URL = "https://myapp.com/callback";

    private Client activeClient;
    private Client inactiveClient;

    @BeforeEach
    void setUp() {
        // Arrange: Setup standard state for most tests
        Client client1 = Client.builder()
                .name(ACTIVE_CLIENT_NAME)
                .clientSecret(CLIENT_SECRET)
                .redirectUrl(REDIRECT_URL)
                .isActive(true)
                .build();

        Client client2 = Client.builder()
                .name(INACTIVE_CLIENT_NAME)
                .clientSecret(CLIENT_SECRET)
                .redirectUrl(REDIRECT_URL)
                .isActive(false) // Explicitly inactive
                .build();

        activeClient = entityManager.persistAndFlush(client1);
        inactiveClient = entityManager.persistAndFlush(client2);
    }

    @Test
    @DisplayName("Should return client when ID exists and isActive is true")
    void findByIdAndIsActiveTrue_WhenActive_ShouldReturnClient() {
        // Act
        Optional<Client> found = clientRepository.findByIdAndIsActiveTrue(activeClient.getId());

        // Assert
        assertThat(found).isPresent();
        assertThat(found.get().getName()).isEqualTo(ACTIVE_CLIENT_NAME);
        assertThat(found.get().getIsActive()).isTrue();
    }

    @Test
    @DisplayName("Should return empty when ID exists but isActive is false")
    void findByIdAndIsActiveTrue_WhenInactive_ShouldReturnEmpty() {
        // Act
        Optional<Client> found = clientRepository.findByIdAndIsActiveTrue(inactiveClient.getId());

        // Assert
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("Should return empty when ID does not exist")
    void findByIdAndIsActiveTrue_WhenWrongId_ShouldReturnEmpty() {
        // Arrange
        UUID randomId = UUID.randomUUID();

        // Act
        Optional<Client> found = clientRepository.findByIdAndIsActiveTrue(randomId);

        // Assert
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("Should return a paginated list of clients")
    void findAll_WhenClientsExist_ShouldReturnPagedResult() {
        // Arrange
        Pageable pageable = PageRequest.of(0, 10);

        // Act
        Page<Client> clientPage = clientRepository.findAll(pageable);

        // Assert
        assertThat(clientPage.getTotalElements()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should return an empty page when no clients exist")
    void findAll_WhenNoClientsExist_ShouldReturnEmptyPage() {
        // Arrange
        clientRepository.deleteAll();
        Pageable pageable = PageRequest.of(0, 10);

        // Act
        Page<Client> clientPage = clientRepository.findAll(pageable);

        // Assert
        assertThat(clientPage.getTotalElements()).isZero();
        assertThat(clientPage.getContent()).isEmpty();
    }

    @Test
    @DisplayName("Should throw exception when saving client without required non-null fields")
    void save_WhenRequiredFieldMissing_ShouldThrowException() {
        // Arrange
        Client invalidClient = Client.builder()
                .clientSecret(CLIENT_SECRET)
                .isActive(true)
                .build();

        // Act & Assert
        assertThrows(PersistenceException.class, () -> {
            entityManager.persistAndFlush(invalidClient);
        });
    }
}
