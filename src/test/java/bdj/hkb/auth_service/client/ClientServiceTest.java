package bdj.hkb.auth_service.client;

import bdj.hkb.auth_service.client.dto.ClientResponse;
import bdj.hkb.auth_service.client.dto.RegisterClientRequest;
import bdj.hkb.auth_service.client.dto.RegisterClientResponse;
import bdj.hkb.auth_service.exceptionHandler.ClientNotFoundException;
import bdj.hkb.auth_service.exceptionHandler.UserNotFoundException;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.security.dto.JwtPrincipal;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientServiceTest {

    @Mock
    private ClientRepository clientRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserRoleRepository userRoleRepository;

    @InjectMocks
    private ClientService clientService;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    @Captor
    private ArgumentCaptor<UserRole> userRoleCaptor;

    // --- Constants ---
    private static final String MASTER_CLIENT_ID = "00000000-0000-0000-0000-000000000000"; // Assuming UUID format for master
    private static final UUID TOKEN_CLIENT_ID_MASTER = UUID.fromString(MASTER_CLIENT_ID);
    private static final UUID TOKEN_CLIENT_ID_TENANT = UUID.randomUUID();
    private static final UUID REQUESTER_USER_ID = UUID.randomUUID();
    private static final UUID SAVED_CLIENT_ID = UUID.randomUUID();
    private static final String NEW_CLIENT_NAME = "New Tenant App";
    private static final String NEW_REDIRECT_URL = "https://tenant.com/callback";
    private static final String HASHED_SECRET = "hashed-secret-value";

    private JwtPrincipal masterPrincipal;
    private JwtPrincipal tenantPrincipal;
    private Client savedClient;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(clientService, "masterClientId", MASTER_CLIENT_ID);

        masterPrincipal = new JwtPrincipal(REQUESTER_USER_ID, TOKEN_CLIENT_ID_MASTER, List.of("ROLE_ADMIN"));
        tenantPrincipal = new JwtPrincipal(REQUESTER_USER_ID, TOKEN_CLIENT_ID_TENANT, List.of("ROLE_ADMIN"));

        savedClient = Client.builder()
                .id(SAVED_CLIENT_ID)
                .name(NEW_CLIENT_NAME)
                .isActive(true)
                .redirectUrl(NEW_REDIRECT_URL)
                .createdAt(OffsetDateTime.now())
                .build();
    }

    // ==========================================
    // Tests for registerClient()
    // ==========================================

    @Test
    @DisplayName("registerClient - Should throw AccessDeniedException if requester is not Master Client")
    void registerClient_WhenNotMaster_ShouldThrowException() {
        // Arrange
        RegisterClientRequest request = new RegisterClientRequest(NEW_CLIENT_NAME, NEW_REDIRECT_URL);

        // Act & Assert
        AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> {
            clientService.registerClient(request, tenantPrincipal);
        });

        assertThat(exception.getMessage()).contains("Only users belonging to the main platform can create new clients");
        verify(clientRepository, never()).saveAndFlush(any());
    }

    @Test
    @DisplayName("registerClient - Should register client and copy LOCAL user properties successfully")
    void registerClient_WhenMasterAndLocalUser_ShouldRegisterSuccessfully() {
        // Arrange
        RegisterClientRequest request = new RegisterClientRequest(NEW_CLIENT_NAME, NEW_REDIRECT_URL);

        User localUser = User.builder()
                .id(REQUESTER_USER_ID)
                .email("admin@platform.com")
                .authProvider("local")
                .passwordHash("original-hash")
                .build();

        when(passwordEncoder.encode(anyString())).thenReturn(HASHED_SECRET);
        when(clientRepository.saveAndFlush(any(Client.class))).thenReturn(savedClient);
        when(userRepository.findById(REQUESTER_USER_ID)).thenReturn(Optional.of(localUser));

        // Act
        RegisterClientResponse response = clientService.registerClient(request, masterPrincipal);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.name()).isEqualTo(NEW_CLIENT_NAME);
        assertThat(response.clientId()).isEqualTo(SAVED_CLIENT_ID);
        assertThat(response.clientSecret()).isNotBlank();

        verify(userRepository).save(userCaptor.capture());
        User createdAdmin = userCaptor.getValue();
        assertThat(createdAdmin.getEmail()).isEqualTo("admin@platform.com");
        assertThat(createdAdmin.getAuthProvider()).isEqualTo("local");
        assertThat(createdAdmin.getPasswordHash()).isEqualTo("original-hash");
        assertThat(createdAdmin.getClient()).isEqualTo(savedClient);

        verify(userRoleRepository).save(userRoleCaptor.capture());
        UserRole createdRole = userRoleCaptor.getValue();
        assertThat(createdRole.getRole()).isEqualTo("ROLE_ADMIN");
        assertThat(createdRole.getClient()).isEqualTo(savedClient);
    }

    @Test
    @DisplayName("registerClient - Should register client and copy OAUTH user properties successfully")
    void registerClient_WhenMasterAndOAuthUser_ShouldRegisterSuccessfully() {
        // Arrange
        RegisterClientRequest request = new RegisterClientRequest(NEW_CLIENT_NAME, NEW_REDIRECT_URL);

        User oauthUser = User.builder()
                .id(REQUESTER_USER_ID)
                .email("oauth@platform.com")
                .authProvider("GOOGLE")
                .providerId("google-123")
                .build();

        when(passwordEncoder.encode(anyString())).thenReturn(HASHED_SECRET);
        when(clientRepository.saveAndFlush(any(Client.class))).thenReturn(savedClient);
        when(userRepository.findById(REQUESTER_USER_ID)).thenReturn(Optional.of(oauthUser));

        // Act
        clientService.registerClient(request, masterPrincipal);

        // Assert
        verify(userRepository).save(userCaptor.capture());
        User createdAdmin = userCaptor.getValue();
        assertThat(createdAdmin.getEmail()).isEqualTo("oauth@platform.com");
        assertThat(createdAdmin.getAuthProvider()).isEqualTo("GOOGLE");
        assertThat(createdAdmin.getProviderId()).isEqualTo("google-123");
        assertThat(createdAdmin.getPasswordHash()).isNull();
    }

    @Test
    @DisplayName("registerClient - Should throw UserNotFoundException if requester ID does not exist")
    void registerClient_WhenRequesterNotFound_ShouldThrowException() {
        // Arrange
        RegisterClientRequest request = new RegisterClientRequest(NEW_CLIENT_NAME, NEW_REDIRECT_URL);

        when(passwordEncoder.encode(anyString())).thenReturn(HASHED_SECRET);
        when(clientRepository.saveAndFlush(any(Client.class))).thenReturn(savedClient);
        when(userRepository.findById(REQUESTER_USER_ID)).thenReturn(Optional.empty());

        // Act & Assert
        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> {
            clientService.registerClient(request, masterPrincipal);
        });

        assertThat(exception.getMessage()).isEqualTo("Requester not found");
        verify(userRoleRepository, never()).save(any());
    }

    // ==========================================
    // Tests for getAllClients()
    // ==========================================

    @Test
    @DisplayName("getAllClients - Should return mapped paginated clients")
    void getAllClients_ShouldReturnPagedResponses() {
        // Arrange
        Pageable pageable = PageRequest.of(0, 10);
        Page<Client> mockPage = new PageImpl<>(List.of(savedClient));
        when(clientRepository.findAll(pageable)).thenReturn(mockPage);

        // Act
        Page<ClientResponse> responses = clientService.getAllClients(pageable);

        // Assert
        assertThat(responses.getTotalElements()).isEqualTo(1);
        assertThat(responses.getContent().get(0).name()).isEqualTo(NEW_CLIENT_NAME);
    }

    // ==========================================
    // Tests for getActiveClientById()
    // ==========================================

    @Test
    @DisplayName("getActiveClientById - Should return ClientResponse when client is active")
    void getActiveClientById_WhenExistsAndActive_ShouldReturnResponse() {
        // Arrange
        when(clientRepository.findByIdAndIsActiveTrue(SAVED_CLIENT_ID)).thenReturn(Optional.of(savedClient));

        // Act
        ClientResponse response = clientService.getActiveClientById(SAVED_CLIENT_ID);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.id()).isEqualTo(SAVED_CLIENT_ID);
        assertThat(response.name()).isEqualTo(NEW_CLIENT_NAME);
    }

    @Test
    @DisplayName("getActiveClientById - Should throw ClientNotFoundException when client doesn't exist or is inactive")
    void getActiveClientById_WhenNotFound_ShouldThrowException() {
        // Arrange
        when(clientRepository.findByIdAndIsActiveTrue(SAVED_CLIENT_ID)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(ClientNotFoundException.class, () -> {
            clientService.getActiveClientById(SAVED_CLIENT_ID);
        });
    }

    // ==========================================
    // Tests for updateRedirectUrl()
    // ==========================================

    @Test
    @DisplayName("updateRedirectUrl - Should update and save client when found")
    void updateRedirectUrl_WhenClientExists_ShouldUpdateUrl() {
        // Arrange
        String updatedUrl = "https://new-url.com/cb";
        when(clientRepository.findById(TOKEN_CLIENT_ID_TENANT)).thenReturn(Optional.of(savedClient));

        // Act
        clientService.updateRedirectUrl(tenantPrincipal, updatedUrl);

        // Assert
        assertThat(savedClient.getRedirectUrl()).isEqualTo(updatedUrl);
        verify(clientRepository).save(savedClient);
    }

    @Test
    @DisplayName("updateRedirectUrl - Should throw ClientNotFoundException when client not found")
    void updateRedirectUrl_WhenClientNotFound_ShouldThrowException() {
        // Arrange
        when(clientRepository.findById(TOKEN_CLIENT_ID_TENANT)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(ClientNotFoundException.class, () -> {
            clientService.updateRedirectUrl(tenantPrincipal, "https://new-url.com/cb");
        });

        verify(clientRepository, never()).save(any());
    }
}
