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

    public void store(String userId, String jti, long expirationMillis) {
        redisTemplate.opsForValue().set(
                PREFIX + userId,
                jti,
                Duration.ofMillis(expirationMillis)
        );
    }

    public boolean isValid(String userId, String jti) {
        String storedJti = redisTemplate.opsForValue().get(PREFIX + userId);
        return jti.equals(storedJti);
    }

    public void revoke(String userId) {
        redisTemplate.delete(PREFIX + userId);
    }
}