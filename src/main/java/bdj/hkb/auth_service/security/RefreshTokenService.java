package bdj.hkb.auth_service.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final StringRedisTemplate redisTemplate;
    private static final String PREFIX = "refresh:";

    public void store(String userId, String clientId, String jti, long expirationMillis) {
        try {
            redisTemplate.opsForValue().set(
                    PREFIX + userId + ":" + clientId,
                    jti,
                    Duration.ofMillis(expirationMillis)
            );
        } catch (Exception e) {
            log.error(
                    "Failed to store refresh token for user {} for client {}",
                    userId,
                    clientId);
            throw new RuntimeException(e);
        }

    }

    public boolean isValid(String userId, String clientId, String jti) {
        try {
            String storedJti = redisTemplate.opsForValue().get(PREFIX + userId + ":" + clientId);
            return jti.equals(storedJti);
        } catch (Exception e) {
            log.error(
                    "Failed to validate refresh token"
            );
            throw new RuntimeException(e);
        }
    }

    public void revoke(String userId, String clientId) {
        try {
            redisTemplate.delete(PREFIX + userId + ":" + clientId);
        } catch (Exception e) {
            log.error("Failed to revoke refresh token");
            throw new RuntimeException(e);
        }
    }
}