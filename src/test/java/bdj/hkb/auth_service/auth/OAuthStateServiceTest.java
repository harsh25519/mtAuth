package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.OAuthStateContext;
import bdj.hkb.auth_service.exceptionHandler.InvalidOAuthStateException;
import bdj.hkb.auth_service.exceptionHandler.OAuthCodeDeserializationException;
import bdj.hkb.auth_service.exceptionHandler.OAuthCodeSerializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuthStateServiceTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;
    @Mock private ObjectMapper objectMapper;

    @InjectMocks
    private OAuthStateService stateService;

    @Captor
    private ArgumentCaptor<OAuthStateContext> contextCaptor;

    // --- Constants ---
    private static final String STATE_KEY_PREFIX = "oauth:state:";
    private static final UUID CLIENT_ID = UUID.randomUUID();
    private static final String MOCK_JSON_CONTEXT = "{\"clientId\":\"mock-id\",\"provider\":\"GOOGLE\",\"timestamp\":123456789}";
    private static final String MOCK_STATE = "secure-random-state-xyz";

    private OAuthProvider targetProvider;
    private OAuthStateContext expectedContext;

    @BeforeEach
    void setUp() {
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        targetProvider = OAuthProvider.GOOGLE;
        expectedContext = new OAuthStateContext(CLIENT_ID, targetProvider, System.currentTimeMillis());
    }

    // ==========================================
    // Tests for generateAndSaveState()
    // ==========================================

    @Test
    @DisplayName("generateAndSaveState - Should create context, serialize, save to Redis, and return state string")
    void generateAndSaveState_WhenValid_ShouldSaveAndReturnState() throws JsonProcessingException {
        // Arrange
        when(objectMapper.writeValueAsString(any(OAuthStateContext.class))).thenReturn(MOCK_JSON_CONTEXT);

        // Act
        String state = stateService.generateAndSaveState(CLIENT_ID, targetProvider);

        // Assert
        assertThat(state).isNotBlank();

        verify(objectMapper).writeValueAsString(contextCaptor.capture());
        OAuthStateContext capturedContext = contextCaptor.getValue();
        assertThat(capturedContext.clientId()).isEqualTo(CLIENT_ID);
        assertThat(capturedContext.provider()).isEqualTo(targetProvider);

        verify(valueOperations).set(
                eq(STATE_KEY_PREFIX + state),
                eq(MOCK_JSON_CONTEXT),
                eq(Duration.ofMinutes(10))
        );
    }

    @Test
    @DisplayName("generateAndSaveState - Should throw OAuth2AuthenticationException if Jackson serialization fails")
    void generateAndSaveState_WhenSerializationFails_ShouldThrowException() throws JsonProcessingException {
        // Arrange
        JsonProcessingException mockException = mock(JsonProcessingException.class);
        when(objectMapper.writeValueAsString(any(OAuthStateContext.class))).thenThrow(mockException);

        // Act & Assert
        OAuthCodeSerializationException exception = assertThrows(OAuthCodeSerializationException.class, () -> {
            stateService.generateAndSaveState(CLIENT_ID, targetProvider);
        });

        assertThat(exception.getMessage()).isEqualTo("Failed to serialize OAuth state context");
        verify(valueOperations, never()).set(anyString(), anyString(), any(Duration.class));
    }

    // ==========================================
    // Tests for validateAndConsumeState()
    // ==========================================

    @Test
    @DisplayName("validateAndConsumeState - Should fetch from Redis, burn the key, deserialize, and return")
    void validateAndConsumeState_WhenValid_ShouldConsumeAndBurnKey() throws JsonProcessingException {
        // Arrange
        String expectedKey = STATE_KEY_PREFIX + MOCK_STATE;
        when(valueOperations.get(expectedKey)).thenReturn(MOCK_JSON_CONTEXT);
        when(objectMapper.readValue(MOCK_JSON_CONTEXT, OAuthStateContext.class)).thenReturn(expectedContext);

        // Act
        OAuthStateContext result = stateService.validateAndConsumeState(MOCK_STATE);

        // Assert
        assertThat(result).isEqualTo(expectedContext);

        verify(redisTemplate).delete(expectedKey);
    }

    @Test
    @DisplayName("validateAndConsumeState - Should throw InvalidOAuthStateException if state is not found in Redis")
    void validateAndConsumeState_WhenNotFound_ShouldThrowException() {
        // Arrange
        String expectedKey = STATE_KEY_PREFIX + MOCK_STATE;
        when(valueOperations.get(expectedKey)).thenReturn(null); // Simulated expiration or invalid state

        // Act & Assert
        InvalidOAuthStateException exception = assertThrows(InvalidOAuthStateException.class, () -> {
            stateService.validateAndConsumeState(MOCK_STATE);
        });

        assertThat(exception.getMessage()).isEqualTo("Invalid or expired OAuth state");

        verify(redisTemplate, never()).delete(anyString());
        verifyNoInteractions(objectMapper);
    }

    @Test
    @DisplayName("validateAndConsumeState - Should delete key and throw OAuthCodeDeserializationException if Jackson fails")
    void validateAndConsumeState_WhenDeserializationFails_ShouldBurnKeyAndThrowException() throws JsonProcessingException {
        // Arrange
        String expectedKey = STATE_KEY_PREFIX + MOCK_STATE;
        String corruptedJson = "{bad-state-json}";

        when(valueOperations.get(expectedKey)).thenReturn(corruptedJson);

        JsonProcessingException mockException = mock(JsonProcessingException.class);
        when(objectMapper.readValue(corruptedJson, OAuthStateContext.class)).thenThrow(mockException);

        // Act & Assert
        OAuthCodeDeserializationException exception = assertThrows(OAuthCodeDeserializationException.class, () -> {
            stateService.validateAndConsumeState(MOCK_STATE);
        });

        assertThat(exception.getMessage()).isEqualTo("Failed to deserialize state context");

        verify(redisTemplate).delete(expectedKey);
    }
}