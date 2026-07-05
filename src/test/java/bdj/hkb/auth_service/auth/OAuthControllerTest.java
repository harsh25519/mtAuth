package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.OAuthExchangeRequest;
import bdj.hkb.auth_service.security.JwtFilter;
import bdj.hkb.auth_service.security.JwtUtilService;
import org.junit.jupiter.api.BeforeEach;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(
        controllers = OAuthController.class,
        excludeAutoConfiguration = {SecurityAutoConfiguration.class}
)
@AutoConfigureMockMvc(addFilters = false)
class OAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper objectMapper;

    @MockitoBean
    private OAuthOrchestratorService orchestratorService;

    @MockitoBean
    private JwtFilter jwtFilter;

    @MockitoBean
    private JwtUtilService jwtUtilService;

    // --- Constants ---
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final String CLIENT_ID_STR = CLIENT_ID.toString();
    private static final String PROVIDER_STR = "google";
    private static final OAuthProvider PROVIDER_ENUM = OAuthProvider.GOOGLE;

    private static final String OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/auth?state=xyz";
    private static final String FRONTEND_REDIRECT_URL = "https://frontend.app/oauth/callback?code=bridge-code";
    private static final String PROVIDER_CODE = "google-auth-code-123";
    private static final String STATE_PARAM = "secure-random-state";
    private static final String BRIDGE_CODE = "bridge-code-xyz";
    private static final String CLIENT_SECRET = "super-secret";

    private AuthResponse authResponse;

    @BeforeEach
    void setUp() {
        authResponse = new AuthResponse("mock-access", "mock-refresh", "Bearer");
    }

    // ==========================================
    // Tests for GET /oauth/{provider}/start
    // ==========================================

    @Test
    @DisplayName("GET /oauth/{provider}/start - Should return 302 Found with Auth URL in Location header")
    void startOAuth_WhenValidRequest_ShouldRedirectToProvider() throws Exception {
        // Arrange
        when(orchestratorService.getAuthorizationUrl(PROVIDER_ENUM, CLIENT_ID))
                .thenReturn(OAUTH_AUTH_URL);

        // Act & Assert
        mockMvc.perform(get("/oauth/{provider}/start", PROVIDER_STR)
                        .param("clientId", CLIENT_ID_STR))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", OAUTH_AUTH_URL));

        verify(orchestratorService).getAuthorizationUrl(PROVIDER_ENUM, CLIENT_ID);
    }

    // ==========================================
    // Tests for GET /oauth/{provider}/callback
    // ==========================================

    @Test
    @DisplayName("GET /oauth/{provider}/callback - Should return 302 Found with Frontend URL in Location header")
    void oauthCallback_WhenValidCallback_ShouldRedirectToFrontend() throws Exception {
        // Arrange
        when(orchestratorService.handleProviderCallback(PROVIDER_ENUM, PROVIDER_CODE, STATE_PARAM))
                .thenReturn(FRONTEND_REDIRECT_URL);

        // Act & Assert
        mockMvc.perform(get("/oauth/{provider}/callback", PROVIDER_STR)
                        .param("code", PROVIDER_CODE)
                        .param("state", STATE_PARAM))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", FRONTEND_REDIRECT_URL));

        verify(orchestratorService).handleProviderCallback(PROVIDER_ENUM, PROVIDER_CODE, STATE_PARAM);
    }

    // ==========================================
    // Tests for POST /oauth/exchange
    // ==========================================

    @Test
    @DisplayName("POST /oauth/exchange - Should return 200 OK with AuthResponse on valid code exchange")
    void exchangeCode_WhenValidRequest_ShouldReturnTokens() throws Exception {
        // Arrange
        OAuthExchangeRequest request = new OAuthExchangeRequest(BRIDGE_CODE, CLIENT_ID, CLIENT_SECRET);

        when(orchestratorService.exchangeCodeForTokens(any(OAuthExchangeRequest.class)))
                .thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/oauth/exchange")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("mock-access"))
                .andExpect(jsonPath("$.refreshToken").value("mock-refresh"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));

        verify(orchestratorService).exchangeCodeForTokens(any(OAuthExchangeRequest.class));
    }
}