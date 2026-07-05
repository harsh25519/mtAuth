package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.exceptionHandler.InvalidOAuthStateException;
import bdj.hkb.auth_service.exceptionHandler.OAuthCodeDeserializationException;
import bdj.hkb.auth_service.exceptionHandler.OAuthCodeSerializationException;
import bdj.hkb.auth_service.security.JwtUtilService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuthCodeServiceTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;
    @Mock private ObjectMapper objectMapper;
    @Mock private JwtUtilService jwtUtilService;

    @InjectMocks
    private OAuthCodeService oAuthCodeService;

    // --- Constants ---
    private static final String CODE_KEY_PREFIX = "oauth:code:";
    private static final String MOCK_AUTH_CODE = UUID.randomUUID().toString();
    private static final String MOCK_JSON_PAYLOAD = "{\"accessToken\":\"mock-access\",\"refreshToken\":\"mock-refresh\",\"tokenType\":\"Bearer\"}";
    private static final String USER_ID = UUID.randomUUID().toString();
    private static final String CLIENT_ID = UUID.randomUUID().toString();

    private AuthResponse authResponse;

    @BeforeEach
    void setUp() {
        authResponse = new AuthResponse("mock-access", "mock-refresh", "Bearer");

        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    // ==========================================
    // Tests for saveAuthResponse()
    // ==========================================

    @Test
    @DisplayName("saveAuthResponse - Should serialize to JSON, save to Redis, and return a UUID string")
    void saveAuthResponse_WhenValid_ShouldSaveAndReturnCode() throws JsonProcessingException {
        // Arrange
        when(objectMapper.writeValueAsString(authResponse)).thenReturn(MOCK_JSON_PAYLOAD);
        when(jwtUtilService.extractUserId("mock-access")).thenReturn(USER_ID);
        when(jwtUtilService.extractClientId("mock-access")).thenReturn(CLIENT_ID);

        // Act
        String authCode = oAuthCodeService.saveAuthResponse(authResponse);

        // Assert
        assertThat(authCode).isNotBlank();

        verify(valueOperations).set(
                eq(CODE_KEY_PREFIX + authCode),
                eq(MOCK_JSON_PAYLOAD),
                eq(Duration.ofSeconds(35))
        );
    }

    @Test
    @DisplayName("saveAuthResponse - Should throw OAuthCodeSerializationException if Jackson fails")
    void saveAuthResponse_WhenSerializationFails_ShouldThrowException() throws JsonProcessingException {
        // Arrange
        JsonProcessingException mockException = mock(JsonProcessingException.class);
        when(objectMapper.writeValueAsString(authResponse)).thenThrow(mockException);

        // Act & Assert
        OAuthCodeSerializationException exception = assertThrows(OAuthCodeSerializationException.class, () -> {
            oAuthCodeService.saveAuthResponse(authResponse);
        });

        assertThat(exception.getMessage()).isEqualTo("Failed to serialize AuthResponse");
        verify(valueOperations, never()).set(anyString(), anyString(), any(Duration.class));
    }

    // ==========================================
    // Tests for consumeAuthCode()
    // ==========================================

    @Test
    @DisplayName("consumeAuthCode - Should fetch from Redis, burn the key, deserialize, and return")
    void consumeAuthCode_WhenValid_ShouldConsumeAndBurnKey() throws JsonProcessingException {
        // Arrange
        String expectedKey = CODE_KEY_PREFIX + MOCK_AUTH_CODE;
        when(valueOperations.get(expectedKey)).thenReturn(MOCK_JSON_PAYLOAD);
        when(objectMapper.readValue(MOCK_JSON_PAYLOAD, AuthResponse.class)).thenReturn(authResponse);

        // Act
        AuthResponse result = oAuthCodeService.consumeAuthCode(MOCK_AUTH_CODE);

        // Assert
        assertThat(result).isEqualTo(authResponse);

        verify(redisTemplate).delete(expectedKey);
    }

    @Test
    @DisplayName("consumeAuthCode - Should throw InvalidOAuthStateException if code is not found in Redis")
    void consumeAuthCode_WhenNotFound_ShouldThrowException() {
        // Arrange
        String expectedKey = CODE_KEY_PREFIX + MOCK_AUTH_CODE;
        when(valueOperations.get(expectedKey)).thenReturn(null); // Simulated expiration or invalid code

        // Act & Assert
        InvalidOAuthStateException exception = assertThrows(InvalidOAuthStateException.class, () -> {
            oAuthCodeService.consumeAuthCode(MOCK_AUTH_CODE);
        });

        assertThat(exception.getMessage()).isEqualTo("Invalid or expired authorization code");

        verify(redisTemplate, never()).delete(anyString());
        verifyNoInteractions(objectMapper);
    }

    @Test
    @DisplayName("consumeAuthCode - Should delete key and throw OAuthCodeDeserializationException if Jackson fails")
    void consumeAuthCode_WhenDeserializationFails_ShouldBurnKeyAndThrowException() throws JsonProcessingException {
        // Arrange
        String expectedKey = CODE_KEY_PREFIX + MOCK_AUTH_CODE;
        String corruptedJson = "{bad-json}";

        when(valueOperations.get(expectedKey)).thenReturn(corruptedJson);

        JsonProcessingException mockException = mock(JsonProcessingException.class);
        when(objectMapper.readValue(corruptedJson, AuthResponse.class)).thenThrow(mockException);

        // Act & Assert
        OAuthCodeDeserializationException exception = assertThrows(OAuthCodeDeserializationException.class, () -> {
            oAuthCodeService.consumeAuthCode(MOCK_AUTH_CODE);
        });

        assertThat(exception.getMessage()).isEqualTo("Failed to deserialize AuthResponse");

        verify(redisTemplate).delete(expectedKey);
    }
}