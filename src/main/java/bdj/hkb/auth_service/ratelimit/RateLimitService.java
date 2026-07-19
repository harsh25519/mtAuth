package bdj.hkb.auth_service.ratelimit;

import bdj.hkb.auth_service.exceptionHandler.TooManyRequestsException;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RateLimitService {

    private final RateLimitProperties properties;
    private final BucketProvider bucketProvider;
    private final RateLimitKeyResolver keyResolver;


    public void checkAndConsume(RateLimitPolicy policy, HttpServletRequest request, String userIdentifier) {
        RateLimitProperties.LimitConfig config = properties.getPolicies().get(policy.name());
        if (config == null) {
            return; // no policy configured -> fail open rather than break the endpoint
        }

        if (config.isKeyByIp()) {
            String ip = keyResolver.resolveIp(request);
            String key = keyResolver.buildKey("ratelimit:" + policy.name() + ":ip", ip);
            enforce(key, policy, config);
        }

        if (config.isKeyByUser() && userIdentifier != null) {
            String key = keyResolver.buildKey("ratelimit:" + policy.name() + ":user", userIdentifier);
            enforce(key, policy, config);
        }
    }

    private void enforce(String key, RateLimitPolicy policy, RateLimitProperties.LimitConfig config) {
        Bucket bucket = bucketProvider.resolveBucket(key, policy.name(), config);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (!probe.isConsumed()) {
            throw new TooManyRequestsException(probe.getNanosToWaitForRefill() / 1_000_000_000);
        }
    }
}

