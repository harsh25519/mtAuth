package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.exceptionHandler.InvalidOAuthStateException;
import bdj.hkb.auth_service.exceptionHandler.OAuthCodeDeserializationException;
import bdj.hkb.auth_service.exceptionHandler.OAuthCodeSerializationException;
import bdj.hkb.auth_service.security.JwtUtilService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuthCodeService {

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final JwtUtilService jwtUtilService;

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

            String userId = jwtUtilService.extractUserId(response.accessToken());
            String clientId = jwtUtilService.extractClientId(response.accessToken());

            log.info(
                    "Generated OAuth authorization code for user {} with client {}",
                    userId,
                    clientId
                    );
            return authCode;
        } catch (JsonProcessingException e) {
            throw new OAuthCodeSerializationException("Failed to serialize AuthResponse", e);
        }
    }

    public AuthResponse consumeAuthCode(String authCode) {
        String key = CODE_KEY_PREFIX + authCode;
        String jsonPayload = redisTemplate.opsForValue().get(key);

        if (jsonPayload != null) {
            redisTemplate.delete(key); // Burn instantly to prevent replay attacks
            try {
                AuthResponse response = objectMapper.readValue(jsonPayload, AuthResponse.class);

                log.info("OAuth authorization code successfully consumed");

                return response;
            } catch (JsonProcessingException e) {
                throw new OAuthCodeDeserializationException("Failed to deserialize AuthResponse", e);
            }
        }
        throw new InvalidOAuthStateException("Invalid or expired authorization code");
    }
}
