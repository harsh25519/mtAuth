package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.OAuthStateContext;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
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

            return state;
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize OAuth state context", e);
        }
    }

    // You will use this in the next phase during the callback
    public OAuthStateContext validateAndConsumeState(String state) {
        String key = STATE_KEY_PREFIX + state;
        String jsonContext = redisTemplate.opsForValue().get(key);

        if (jsonContext != null) {
            redisTemplate.delete(key); // Burn after reading!
            try {
                return objectMapper.readValue(jsonContext, OAuthStateContext.class);
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to deserialize state context", e);
            }
        }
        throw new RuntimeException("Invalid or expired OAuth state");
    }
}
