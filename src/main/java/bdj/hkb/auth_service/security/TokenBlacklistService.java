package bdj.hkb.auth_service.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;
    private static final String PREFIX = "blacklist:";
    private static final String BLACKLIST_CHANNEL = "auth:blacklist";

    public void blacklist(String jti, long remainingMillis) {
        try {
            if (remainingMillis <= 0) return; // already expired, nothing to blacklist

            redisTemplate.opsForValue().set(
                    PREFIX + jti,
                    "true",
                    Duration.ofMillis(remainingMillis)
            );

            // 2. Publish event to channel
            String message = jti + ":" + remainingMillis;
            redisTemplate.convertAndSend(BLACKLIST_CHANNEL, message);
        } catch (Exception e) {
            log.error(
                    "Failed to blacklist and publish jti"
            );
            throw new RuntimeException(e);
        }
    }

    public boolean isBlacklisted(String jti) {
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX + jti));
        } catch (Exception e) {
            log.error("Failed to check blacklisted jti");
            throw new RuntimeException(e);
        }
    }
}
