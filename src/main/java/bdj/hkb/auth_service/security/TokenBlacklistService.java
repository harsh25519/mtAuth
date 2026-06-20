package bdj.hkb.auth_service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;
    private static final String PREFIX = "blacklist:";

    public void blacklist(String jti, long remainingMillis) {
        if (remainingMillis <= 0) return; // already expired, nothing to blacklist

        redisTemplate.opsForValue().set(
                PREFIX + jti,
                "true",
                Duration.ofMillis(remainingMillis)
        );
    }

    public boolean isBlacklisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX + jti));
    }
}
