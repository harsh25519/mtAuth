package bdj.hkb.auth_service.userRole;

import bdj.hkb.auth_service.role.UserRoleController;
import bdj.hkb.auth_service.role.UserRoleService;
import bdj.hkb.auth_service.role.dto.AssignRoleRequest;
import bdj.hkb.auth_service.role.dto.RevokeRoleRequest;
import bdj.hkb.auth_service.security.JwtFilter;
import bdj.hkb.auth_service.security.JwtUtilService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.json.JsonMapper;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(
        controllers = UserRoleController.class,
        excludeAutoConfiguration = {SecurityAutoConfiguration.class} // Prevents 401 Unauthorized fallback
)
@AutoConfigureMockMvc(addFilters = false) // Disables standard security filters for unit testing
class UserRoleControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper objectMapper;

    @MockitoBean
    private UserRoleService userRoleService;

    @MockitoBean
    private JwtFilter jwtFilter;

    @MockitoBean
    private JwtUtilService jwtUtilService;

    // --- Constants ---
    private static final UUID TARGET_USER_ID = UUID.randomUUID();
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final String ROLE_ADMIN = "ROLE_ADMIN";

    // ==========================================
    // Tests for POST /users/roles
    // ==========================================

    @Test
    @DisplayName("POST /users/roles - Should return 201 Created on valid assignment")
    void assignRole_WhenValidRequest_ShouldReturnCreated() throws Exception {
        // Arrange
        AssignRoleRequest request = new AssignRoleRequest(TARGET_USER_ID, CLIENT_ID, ROLE_ADMIN);

        // Act & Assert
        mockMvc.perform(post("/users/roles")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());

        // @AuthenticationPrincipal resolves to null when filters are disabled, so we use any()
        verify(userRoleService).assignRole(any(AssignRoleRequest.class), any());
    }

    @Test
    @DisplayName("POST /users/roles - Should return 400 Bad Request when role is blank")
    void assignRole_WhenInvalidRequest_ShouldReturnBadRequest() throws Exception {
        // Arrange - Blank role triggers @NotBlank validation failure
        AssignRoleRequest request = new AssignRoleRequest(TARGET_USER_ID, CLIENT_ID, "");

        // Act & Assert
        mockMvc.perform(post("/users/roles")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verify(userRoleService, never()).assignRole(any(), any());
    }

    // ==========================================
    // Tests for DELETE /users/roles
    // ==========================================

    @Test
    @DisplayName("DELETE /users/roles - Should return 204 No Content on valid revocation")
    void revokeRole_WhenValidRequest_ShouldReturnNoContent() throws Exception {
        // Arrange
        RevokeRoleRequest request = new RevokeRoleRequest(TARGET_USER_ID, CLIENT_ID, ROLE_ADMIN);

        // Act & Assert
        mockMvc.perform(delete("/users/roles")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNoContent());

        verify(userRoleService).revokeRole(any(RevokeRoleRequest.class), any());
    }

    @Test
    @DisplayName("DELETE /users/roles - Should return 400 Bad Request when missing IDs")
    void revokeRole_WhenInvalidRequest_ShouldReturnBadRequest() throws Exception {
        // Arrange - Null UUIDs trigger @NotNull validation failure
        RevokeRoleRequest request = new RevokeRoleRequest(null, null, ROLE_ADMIN);

        // Act & Assert
        mockMvc.perform(delete("/users/roles")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verify(userRoleService, never()).revokeRole(any(), any());
    }
}
