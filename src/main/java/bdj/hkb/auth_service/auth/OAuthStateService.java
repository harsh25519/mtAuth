package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.OAuthStateContext;
import bdj.hkb.auth_service.exceptionHandler.InvalidOAuthStateException;
import bdj.hkb.auth_service.exceptionHandler.OAuthCodeDeserializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuthStateService {

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    private static final String STATE_KEY_PREFIX = "oauth:state:";
    private static final long STATE_TTL_MINUTES = 10;

    public String generateAndSaveState(UUID clientId, OAuthProvider provider) {
        try {
            String state = UUID.randomUUID().toString();
            OAuthStateContext context = new OAuthStateContext(clientId, provider, System.currentTimeMillis());

            String jsonContext = objectMapper.writeValueAsString(context);

            redisTemplate.opsForValue().set(
                    STATE_KEY_PREFIX + state,
                    jsonContext,
                    Duration.ofMinutes(STATE_TTL_MINUTES)
            );

            log.info(
                    "Generated OAuth state for client {} and provider {}",
                    clientId,
                    provider
            );

            return state;
        } catch (JsonProcessingException e) {
            throw new OAuth2AuthenticationException("Failed to serialize OAuth state context");
        }
    }

    public OAuthStateContext validateAndConsumeState(String state) {
        String key = STATE_KEY_PREFIX + state;
        String jsonContext = redisTemplate.opsForValue().get(key);

        if (jsonContext != null) {
            redisTemplate.delete(key); // Burn after reading!
            try {
                OAuthStateContext context = objectMapper.readValue(jsonContext, OAuthStateContext.class);

                log.info(
                        "Validated OAuth state for client {} and provider {}",
                        context.clientId(),
                        context.provider()
                );

                return context;
            } catch (JsonProcessingException e) {
                log.error(
                        "Failed to deserialize OAuth state",
                        e
                );
                throw new OAuthCodeDeserializationException("Failed to deserialize state context");
            }
        }
        throw new InvalidOAuthStateException("Invalid or expired OAuth state");
    }
}
