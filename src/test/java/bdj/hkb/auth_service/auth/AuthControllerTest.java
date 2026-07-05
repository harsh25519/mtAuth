package bdj.hkb.auth_service.auth;


import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.LocalLoginRequest;
import bdj.hkb.auth_service.auth.dto.LocalSignupRequest;
import bdj.hkb.auth_service.security.JwtFilter;
import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.security.dto.RefreshTokenRequest;
import bdj.hkb.auth_service.user.emailVerification.EmailVerificationService;
import bdj.hkb.auth_service.user.emailVerification.dto.ResendVerificationRequest;
import bdj.hkb.auth_service.user.passwordReset.PasswordResetService;
import bdj.hkb.auth_service.user.passwordReset.dto.ForgotPasswordRequest;
import bdj.hkb.auth_service.user.passwordReset.dto.ResetPasswordExecutionRequest;
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
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = AuthController.class,
        excludeAutoConfiguration = {SecurityAutoConfiguration.class}
)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JsonMapper objectMapper;

    @MockitoBean
    private AuthService authService;
    @MockitoBean
    private EmailVerificationService emailVerificationService;
    @MockitoBean
    private LocalAuthOrchestrator localAuthOrchestrator;
    @MockitoBean
    private PasswordResetService passwordResetService;
    @MockitoBean
    private JwtFilter jwtFilter;
    @MockitoBean
    private JwtUtilService jwtUtilService;

    // --- Constants ---
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final String VALID_EMAIL = "test@example.com";
    private static final String PASSWORD = "SecurePassword123!";
    private static final String CLIENT_SECRET = "super-secret";
    private static final String MOCK_TOKEN = "mock.jwt.token";

    private AuthResponse authResponse;

    @BeforeEach
    void setUp() {
        authResponse = new AuthResponse("access", "refresh", "Bearer");
    }

    // ==========================================
    // Tests for /auth/signup
    // ==========================================

    @Test
    @DisplayName("POST /auth/signup - Should return 200 OK with success message on valid request")
    void signup_WhenValid_ShouldReturnOk() throws Exception {
        // Arrange
        LocalSignupRequest request = new LocalSignupRequest(VALID_EMAIL, PASSWORD, CLIENT_ID, CLIENT_SECRET);
        doNothing().when(localAuthOrchestrator).registerUserAndDispatchEmail(any(LocalSignupRequest.class));

        // Act & Assert
        mockMvc.perform(post("/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Registration successful. Please check your email to verify your account."));

        verify(localAuthOrchestrator).registerUserAndDispatchEmail(any(LocalSignupRequest.class));
    }

    @Test
    @DisplayName("POST /auth/signup - Should return 400 Bad Request if email is invalid")
    void signup_WhenEmailInvalid_ShouldReturnBadRequest() throws Exception {
        // Arrange
        LocalSignupRequest request = new LocalSignupRequest("not-an-email", PASSWORD, CLIENT_ID, CLIENT_SECRET);

        // Act & Assert
        mockMvc.perform(post("/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());

        verify(localAuthOrchestrator, never()).registerUserAndDispatchEmail(any());
    }

    // ==========================================
    // Tests for /auth/login
    // ==========================================

    @Test
    @DisplayName("POST /auth/login - Should return 200 OK with AuthResponse on valid credentials")
    void login_WhenValid_ShouldReturnAuthResponse() throws Exception {
        // Arrange
        LocalLoginRequest request = new LocalLoginRequest(VALID_EMAIL, PASSWORD, CLIENT_ID);
        when(authService.authenticateLocalUser(any(LocalLoginRequest.class))).thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access"))
                .andExpect(jsonPath("$.refreshToken").value("refresh"));
    }

    // ==========================================
    // Tests for /auth/logout
    // ==========================================

    @Test
    @DisplayName("POST /auth/logout - Should extract token and return 204 No Content")
    void logout_WhenValidHeader_ShouldReturnNoContent() throws Exception {
        // Arrange
        String authHeader = "Bearer " + MOCK_TOKEN;
        doNothing().when(authService).logout(MOCK_TOKEN);

        // Act & Assert
        mockMvc.perform(post("/auth/logout")
                        .with(csrf())
                        .header("Authorization", authHeader))
                .andExpect(status().isNoContent());

        verify(authService).logout(MOCK_TOKEN);
    }

    // ==========================================
    // Tests for /auth/refresh
    // ==========================================

    @Test
    @DisplayName("POST /auth/refresh - Should return 200 OK with new AuthResponse")
    void refresh_WhenValidToken_ShouldReturnOk() throws Exception {
        // Arrange
        RefreshTokenRequest request = new RefreshTokenRequest("valid-refresh-token");
        when(authService.refreshAccessToken("valid-refresh-token")).thenReturn(authResponse);

        // Act & Assert
        mockMvc.perform(post("/auth/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access"));
    }

    // ==========================================
    // Tests for /auth/verify-email
    // ==========================================

    @Test
    @DisplayName("GET /auth/verify-email - Should parse query param and return 200 OK")
    void verifyEmail_WhenValidToken_ShouldReturnOk() throws Exception {
        // Arrange
        doNothing().when(emailVerificationService).verifyEmail(MOCK_TOKEN);

        // Act & Assert
        mockMvc.perform(get("/auth/verify-email")
                        .param("token", MOCK_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Email verified successfully. You can now log in."));

        verify(emailVerificationService).verifyEmail(MOCK_TOKEN);
    }

    // ==========================================
    // Tests for /auth/resend-verification
    // ==========================================

    @Test
    @DisplayName("POST /auth/resend-verification - Should return 200 OK on valid request")
    void resendVerification_WhenValid_ShouldReturnOk() throws Exception {
        // Arrange
        ResendVerificationRequest request = new ResendVerificationRequest(VALID_EMAIL, CLIENT_ID);
        doNothing().when(localAuthOrchestrator).resendVerificationEmail(any(ResendVerificationRequest.class));

        // Act & Assert
        mockMvc.perform(post("/auth/resend-verification")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("If an account exists and is unverified, a new link has been sent."));
    }

    // ==========================================
    // Tests for /auth/forgot-password
    // ==========================================

    @Test
    @DisplayName("POST /auth/forgot-password - Should return 200 OK on valid request")
    void forgotPassword_WhenValid_ShouldReturnOk() throws Exception {
        // Arrange
        ForgotPasswordRequest request = new ForgotPasswordRequest(VALID_EMAIL, CLIENT_ID);
        doNothing().when(localAuthOrchestrator).requestPasswordReset(any(ForgotPasswordRequest.class));

        // Act & Assert
        mockMvc.perform(post("/auth/forgot-password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("If an account with that email exists, a password reset link has been sent."));
    }

    // ==========================================
    // Tests for /auth/reset-password
    // ==========================================

    @Test
    @DisplayName("POST /auth/reset-password - Should parse query param and body, then return 200 OK")
    void resetPassword_WhenValidTokenAndBody_ShouldReturnOk() throws Exception {
        // Arrange
        ResetPasswordExecutionRequest request = new ResetPasswordExecutionRequest("NewPassword123!");
        doNothing().when(passwordResetService).executePasswordReset(MOCK_TOKEN, "NewPassword123!");

        // Act & Assert
        mockMvc.perform(post("/auth/reset-password")
                        .with(csrf())
                        .param("token", MOCK_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password has been successfully reset. You can now log in."));

        verify(passwordResetService).executePasswordReset(MOCK_TOKEN, "NewPassword123!");
    }
}
