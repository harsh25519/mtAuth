package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;
import bdj.hkb.auth_service.auth.dto.OAuthExchangeRequest;
import bdj.hkb.auth_service.auth.dto.OAuthStateContext;
import bdj.hkb.auth_service.auth.strategy.OAuthProviderStrategy;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.exceptionHandler.InvalidClientSecretException;
import bdj.hkb.auth_service.exceptionHandler.InvalidOAuthProviderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuthOrchestratorServiceTest {

    @Mock private ClientRepository clientRepository;
    @Mock private OAuthStateService stateService;
    @Mock private OAuthCodeService codeService;
    @Mock private OAuth2Service oAuth2Service;
    @Mock private PasswordEncoder passwordEncoder;

    @Mock private OAuthProviderStrategy googleStrategy;

    private OAuthOrchestratorService orchestratorService;

    // --- Constants ---
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final String STATE_STRING = "secure-random-state-123";
    private static final String AUTH_CODE = "bridge-code-xyz";
    private static final String PROVIDER_CODE = "google-auth-code";
    private static final String REDIRECT_URL = "https://frontend.app";
    private static final String RAW_SECRET = "raw-secret";
    private static final String ENCODED_SECRET = "encoded-secret";

    private Client mockClient;

    @BeforeEach
    void setUp() {
        // 1. Setup the Strategy Mock to identify itself as GOOGLE
        lenient().when(googleStrategy.getProvider()).thenReturn(OAuthProvider.GOOGLE);

        // 2. Manually initialize the service to trigger the Map conversion logic
        orchestratorService = new OAuthOrchestratorService(
                clientRepository,
                stateService,
                List.of(googleStrategy),
                codeService,
                oAuth2Service,
                passwordEncoder
        );

        mockClient = Client.builder()
                .id(CLIENT_ID)
                .clientSecret(ENCODED_SECRET)
                .redirectUrl(REDIRECT_URL)
                .isActive(true)
                .build();
    }

    // ==========================================
    // Tests for getAuthorizationUrl()
    // ==========================================

    @Test
    @DisplayName("getAuthorizationUrl - Should generate valid provider URL")
    void getAuthorizationUrl_WhenValid_ShouldReturnUrl() {
        // Arrange
        String expectedUrl = "https://google.com/oauth?state=" + STATE_STRING;

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(stateService.generateAndSaveState(CLIENT_ID, OAuthProvider.GOOGLE)).thenReturn(STATE_STRING);
        when(googleStrategy.buildAuthorizationUrl(STATE_STRING)).thenReturn(expectedUrl);

        // Act
        String result = orchestratorService.getAuthorizationUrl(OAuthProvider.GOOGLE, CLIENT_ID);

        // Assert
        assertThat(result).isEqualTo(expectedUrl);
        verify(stateService).generateAndSaveState(CLIENT_ID, OAuthProvider.GOOGLE);
    }

    @Test
    @DisplayName("getAuthorizationUrl - Should throw IllegalArgumentException for unsupported provider")
    void getAuthorizationUrl_WhenStrategyMissing_ShouldThrowException() {
        // Arrange
        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(stateService.generateAndSaveState(CLIENT_ID, OAuthProvider.GITHUB)).thenReturn(STATE_STRING);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            orchestratorService.getAuthorizationUrl(OAuthProvider.GITHUB, CLIENT_ID);
        });

        assertThat(exception.getMessage()).contains("No strategy configured for provider");
    }

    // ==========================================
    // Tests for handleProviderCallback()
    // ==========================================

    @Test
    @DisplayName("handleProviderCallback - Should process user, lock tokens, and return redirect URL")
    void handleProviderCallback_WhenValid_ShouldReturnRedirectUrl() {
        // Arrange
        long mockTimestamp = System.currentTimeMillis();
        OAuthStateContext context = new OAuthStateContext(CLIENT_ID, OAuthProvider.GOOGLE, mockTimestamp);
        OAuth2UserInfo userInfo = mock(OAuth2UserInfo.class);

        AuthResponse tokens = new AuthResponse("mock-access", "mock-refresh", "Bearer");

        when(stateService.validateAndConsumeState(STATE_STRING)).thenReturn(context);
        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(googleStrategy.fetchUserInfo(PROVIDER_CODE)).thenReturn(userInfo);
        when(oAuth2Service.processOAuthUser(mockClient, userInfo, OAuthProvider.GOOGLE)).thenReturn(tokens);
        when(codeService.saveAuthResponse(tokens)).thenReturn(AUTH_CODE);

        // Act
        String redirectUrl = orchestratorService.handleProviderCallback(OAuthProvider.GOOGLE, PROVIDER_CODE, STATE_STRING);

        // Assert
        assertThat(redirectUrl).isEqualTo(REDIRECT_URL + "/oauth/callback?code=" + AUTH_CODE);

        verify(googleStrategy).fetchUserInfo(PROVIDER_CODE);
        verify(oAuth2Service).processOAuthUser(mockClient, userInfo, OAuthProvider.GOOGLE);
        verify(codeService).saveAuthResponse(tokens);
    }

    @Test
    @DisplayName("handleProviderCallback - Should throw exception on Provider hijacking attempt (State mismatch)")
    void handleProviderCallback_WhenProviderMismatch_ShouldThrowException() {
        // Arrange
        long mockTimestamp = System.currentTimeMillis();
        OAuthStateContext hijackedContext = new OAuthStateContext(CLIENT_ID, OAuthProvider.GITHUB, mockTimestamp);
        when(stateService.validateAndConsumeState(STATE_STRING)).thenReturn(hijackedContext);

        // Act & Assert
        InvalidOAuthProviderException exception = assertThrows(InvalidOAuthProviderException.class, () -> {
            orchestratorService.handleProviderCallback(OAuthProvider.GOOGLE, PROVIDER_CODE, STATE_STRING);
        });

        assertThat(exception.getMessage()).isEqualTo("OAuth provider mismatch");

        verify(googleStrategy, never()).fetchUserInfo(anyString());
    }

    // ==========================================
    // Tests for exchangeCodeForTokens()
    // ==========================================

    @Test
    @DisplayName("exchangeCodeForTokens - Should validate secret, consume code, and return tokens")
    void exchangeCodeForTokens_WhenValid_ShouldReturnTokens() {
        // Arrange
        OAuthExchangeRequest request = new OAuthExchangeRequest(AUTH_CODE, CLIENT_ID, RAW_SECRET);

        AuthResponse expectedTokens = new AuthResponse("access", "refresh", "Bearer");

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(passwordEncoder.matches(RAW_SECRET, ENCODED_SECRET)).thenReturn(true);
        when(codeService.consumeAuthCode(AUTH_CODE)).thenReturn(expectedTokens);

        // Act
        AuthResponse result = orchestratorService.exchangeCodeForTokens(request);

        // Assert
        assertThat(result).isEqualTo(expectedTokens);
        verify(codeService).consumeAuthCode(AUTH_CODE);
    }

    @Test
    @DisplayName("exchangeCodeForTokens - Should throw InvalidClientSecretException for wrong secret")
    void exchangeCodeForTokens_WhenInvalidSecret_ShouldThrowException() {
        // Arrange
        OAuthExchangeRequest request = new OAuthExchangeRequest(AUTH_CODE, CLIENT_ID, "wrong-secret");

        when(clientRepository.findByIdAndIsActiveTrue(CLIENT_ID)).thenReturn(Optional.of(mockClient));
        when(passwordEncoder.matches("wrong-secret", ENCODED_SECRET)).thenReturn(false);

        // Act & Assert
        assertThrows(InvalidClientSecretException.class, () -> {
            orchestratorService.exchangeCodeForTokens(request);
        });

        verify(codeService, never()).consumeAuthCode(anyString());
    }
}