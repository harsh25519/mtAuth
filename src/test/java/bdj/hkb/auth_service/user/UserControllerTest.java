package bdj.hkb.auth_service.user;

import bdj.hkb.auth_service.security.JwtFilter;
import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.user.dto.UserResponse;
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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(
        controllers = UserController.class,
        excludeAutoConfiguration = {SecurityAutoConfiguration.class} // Prevents 401 Unauthorized fallback
)
@AutoConfigureMockMvc(addFilters = false) // Disables standard security filters for unit testing
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private JwtUtilService jwtUtil;

    @MockitoBean
    private JwtFilter jwtFilter;

    // --- Constants ---
    private static final UUID TARGET_USER_ID = UUID.randomUUID();
    private static final UUID TARGET_CLIENT_ID = UUID.randomUUID();
    private static final String TOKEN_CLIENT_ID_STR = UUID.randomUUID().toString();
    private static final String MOCK_TOKEN = "mock.jwt.token";
    private static final String AUTH_HEADER = "Bearer " + MOCK_TOKEN;

    private UserResponse userResponse;

    @BeforeEach
    void setUp() {
        userResponse = new UserResponse(
                TARGET_USER_ID,
                "user@example.com",
                TARGET_CLIENT_ID,
                true,
                "local",
                List.of("ROLE_USER"),
                OffsetDateTime.now()
        );
    }

    // ==========================================
    // Tests for GET /users
    // ==========================================

    @Test
    @DisplayName("GET /users - Should return 200 OK with paginated users across all tenants")
    void getAllUsers_WhenValidRequest_ShouldReturnPage() throws Exception {
        // Arrange
        Page<UserResponse> pagedResponse = new PageImpl<>(List.of(userResponse));

        when(jwtUtil.extractClientId(MOCK_TOKEN)).thenReturn(TOKEN_CLIENT_ID_STR);
        when(userService.getAllUsers(eq(TOKEN_CLIENT_ID_STR), any(Pageable.class))).thenReturn(pagedResponse);

        // Act & Assert
        mockMvc.perform(get("/users")
                        .header("Authorization", AUTH_HEADER)
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(TARGET_USER_ID.toString()))
                .andExpect(jsonPath("$.content[0].email").value("user@example.com"))
                .andExpect(jsonPath("$.totalElements").value(1));

        verify(jwtUtil).extractClientId(MOCK_TOKEN);
        verify(userService).getAllUsers(eq(TOKEN_CLIENT_ID_STR), any(Pageable.class));
    }

    // ==========================================
    // Tests for GET /users/client/{clientId}
    // ==========================================

    @Test
    @DisplayName("GET /users/client/{clientId} - Should return 200 OK with paginated users for specific tenant")
    void getUsersByClientId_WhenValidRequest_ShouldReturnPage() throws Exception {
        // Arrange
        Page<UserResponse> pagedResponse = new PageImpl<>(List.of(userResponse));

        when(jwtUtil.extractClientId(MOCK_TOKEN)).thenReturn(TOKEN_CLIENT_ID_STR);
        when(userService.getUsersByClientId(eq(TARGET_CLIENT_ID), eq(TOKEN_CLIENT_ID_STR), any(Pageable.class)))
                .thenReturn(pagedResponse);

        // Act & Assert
        mockMvc.perform(get("/users/client/{clientId}", TARGET_CLIENT_ID)
                        .header("Authorization", AUTH_HEADER)
                        .param("page", "1")
                        .param("size", "20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(TARGET_USER_ID.toString()))
                .andExpect(jsonPath("$.totalElements").value(1));

        verify(jwtUtil).extractClientId(MOCK_TOKEN);
        verify(userService).getUsersByClientId(eq(TARGET_CLIENT_ID), eq(TOKEN_CLIENT_ID_STR), any(Pageable.class));
    }

    // ==========================================
    // Tests for GET /users/{userId}
    // ==========================================

    @Test
    @DisplayName("GET /users/{userId} - Should return 200 OK with single user response")
    void getUserById_WhenValidRequest_ShouldReturnUser() throws Exception {
        // Arrange
        when(jwtUtil.extractClientId(MOCK_TOKEN)).thenReturn(TOKEN_CLIENT_ID_STR);
        when(userService.getUserById(TARGET_USER_ID, TOKEN_CLIENT_ID_STR)).thenReturn(userResponse);

        // Act & Assert
        mockMvc.perform(get("/users/{userId}", TARGET_USER_ID)
                        .header("Authorization", AUTH_HEADER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(TARGET_USER_ID.toString()))
                .andExpect(jsonPath("$.email").value("user@example.com"));

        verify(jwtUtil).extractClientId(MOCK_TOKEN);
        verify(userService).getUserById(TARGET_USER_ID, TOKEN_CLIENT_ID_STR);
    }
}