package bdj.hkb.auth_service.ratelimit;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;

@Getter
@Setter
@ConfigurationProperties(prefix = "ratelimit")
public class RateLimitProperties {

    private Map<String, LimitConfig> policies;

    @Setter
    @Getter
    public static class LimitConfig {
        private int capacity;
        private Duration refill;
        private boolean keyByUser = true;
        private boolean keyByIp = true;

    }
}