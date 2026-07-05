package bdj.hkb.auth_service.client;

import bdj.hkb.auth_service.client.dto.ClientResponse;
import bdj.hkb.auth_service.client.dto.RegisterClientRequest;
import bdj.hkb.auth_service.client.dto.RegisterClientResponse;
import bdj.hkb.auth_service.client.dto.UpdateRedirectUrlRequest;
import bdj.hkb.auth_service.security.JwtFilter;
import bdj.hkb.auth_service.security.JwtUtilService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(
        controllers = ClientController.class,
        excludeAutoConfiguration = {SecurityAutoConfiguration.class} // Prevents 401 Unauthorized fallback
)
@AutoConfigureMockMvc(addFilters = false) // Disables standard security filters for unit testing
class ClientControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper objectMapper;

    @MockitoBean
    private ClientService clientService;

    @MockitoBean
    private JwtUtilService jwtUtilService;

    @MockitoBean
    private JwtFilter jwtFilter;


    // --- Constants ---
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final String CLIENT_NAME = "Test Tenant";
    private static final String REDIRECT_URL = "https://tenant.app/callback";
    private static final String RAW_SECRET = "raw-secret-key-123";

    private ClientResponse clientResponse;
    private RegisterClientResponse registerClientResponse;

    @BeforeEach
    void setUp() {
        clientResponse = new ClientResponse(
                CLIENT_ID,
                CLIENT_NAME,
                true,
                OffsetDateTime.now()
        );

        registerClientResponse = new RegisterClientResponse(
                CLIENT_NAME,
                CLIENT_ID,
                RAW_SECRET,
                "Warning: Copy this clientSecret immediately."
        );
    }

    // ==========================================
    // Tests for POST /clients/register
    // ==========================================

    @Test
    @DisplayName("POST /clients/register - Should return 201 Created on valid request")
    void registerClient_WhenValid_ShouldReturnCreated() throws Exception {
        // Arrange
        RegisterClientRequest request = new RegisterClientRequest(CLIENT_NAME, REDIRECT_URL);

        // @AuthenticationPrincipal resolves to null when filters are disabled, so we use any()
        when(clientService.registerClient(any(RegisterClientRequest.class), any())).thenReturn(registerClientResponse);

        // Act & Assert
        mockMvc.perform(post("/clients/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value(CLIENT_NAME))
                .andExpect(jsonPath("$.clientId").value(CLIENT_ID.toString()))
                .andExpect(jsonPath("$.clientSecret").value(RAW_SECRET));

        verify(clientService).registerClient(any(RegisterClientRequest.class), any());
    }

    @Test
    @DisplayName("POST /clients/register - Should return 400 Bad Request if validation fails")
    void registerClient_WhenInvalid_ShouldReturnBadRequest() throws Exception {
        // Arrange: Missing name to trigger @Valid failure
        RegisterClientRequest request = new RegisterClientRequest("", REDIRECT_URL);

        // Act & Assert
        mockMvc.perform(post("/clients/register")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verify(clientService, never()).registerClient(any(), any());
    }

    // ==========================================
    // Tests for GET /clients/{clientId}
    // ==========================================

    @Test
    @DisplayName("GET /clients/{clientId} - Should return 200 OK with ClientResponse")
    void getClientById_WhenValid_ShouldReturnClient() throws Exception {
        // Arrange
        when(clientService.getActiveClientById(CLIENT_ID)).thenReturn(clientResponse);

        // Act & Assert
        mockMvc.perform(get("/clients/{clientId}", CLIENT_ID))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(CLIENT_ID.toString()))
                .andExpect(jsonPath("$.name").value(CLIENT_NAME))
                .andExpect(jsonPath("$.isActive").value(true));

        verify(clientService).getActiveClientById(CLIENT_ID);
    }

    // ==========================================
    // Tests for GET /clients
    // ==========================================

    @Test
    @DisplayName("GET /clients - Should return 200 OK with paginated clients")
    void getClients_WhenValid_ShouldReturnPage() throws Exception {
        // Arrange
        Page<ClientResponse> pagedResponse = new PageImpl<>(List.of(clientResponse));
        when(clientService.getAllClients(any(Pageable.class))).thenReturn(pagedResponse);

        // Act & Assert
        mockMvc.perform(get("/clients")
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(CLIENT_ID.toString()))
                .andExpect(jsonPath("$.content[0].name").value(CLIENT_NAME))
                .andExpect(jsonPath("$.totalElements").value(1));

        verify(clientService).getAllClients(any(Pageable.class));
    }

    // ==========================================
    // Tests for PUT /clients/update/redirect-url
    // ==========================================

    @Test
    @DisplayName("PUT /clients/update/redirect-url - Should return 200 OK on success")
    void updateRedirectUrl_WhenValid_ShouldReturnOk() throws Exception {
        // Arrange
        String newUrl = "https://new-tenant.app/callback";
        UpdateRedirectUrlRequest request = new UpdateRedirectUrlRequest(newUrl);

        doNothing().when(clientService).updateRedirectUrl(any(), eq(newUrl));

        // Act & Assert
        mockMvc.perform(put("/clients/update/redirect-url")
                        .with(csrf()) // Required for PUT
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Redirect URL updated successfully"));

        verify(clientService).updateRedirectUrl(any(), eq(newUrl));
    }
}
