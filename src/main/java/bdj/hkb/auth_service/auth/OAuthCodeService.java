package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class OAuthCodeService {

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    private static final String CODE_KEY_PREFIX = "oauth:code:";
    private static final long CODE_TTL_SECONDS = 35;

    public String saveAuthResponse(AuthResponse response) {
        try {
            String authCode = UUID.randomUUID().toString();
            String jsonPayload = objectMapper.writeValueAsString(response);

            redisTemplate.opsForValue().set(
                    CODE_KEY_PREFIX + authCode,
                    jsonPayload,
                    Duration.ofSeconds(CODE_TTL_SECONDS)
            );

            return authCode;
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize AuthResponse", e);
        }
    }

    public AuthResponse consumeAuthCode(String authCode) {
        String key = CODE_KEY_PREFIX + authCode;
        String jsonPayload = redisTemplate.opsForValue().get(key);

        if (jsonPayload != null) {
            redisTemplate.delete(key); // Burn instantly to prevent replay attacks
            try {
                return objectMapper.readValue(jsonPayload, AuthResponse.class);
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to deserialize AuthResponse", e);
            }
        }
        throw new RuntimeException("Invalid or expired authorization code");
    }
}
