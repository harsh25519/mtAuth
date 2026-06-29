package bdj.hkb.auth_service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final StringRedisTemplate redisTemplate;
    private static final String PREFIX = "refresh:";

    public void store(String userId, String clientId, String jti, long expirationMillis) {
        redisTemplate.opsForValue().set(
                PREFIX + userId + ":" + clientId,
                jti,
                Duration.ofMillis(expirationMillis)
        );
    }

    public boolean isValid(String userId, String clientId, String jti) {
        String storedJti = redisTemplate.opsForValue().get(PREFIX + userId + ":" + clientId);
        return jti.equals(storedJti);
    }

    public void revoke(String userId, String clientId) {
        redisTemplate.delete(PREFIX + userId + ":" + clientId);
    }
}