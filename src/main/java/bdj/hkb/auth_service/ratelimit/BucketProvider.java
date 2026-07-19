package bdj.hkb.auth_service.ratelimit;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
@RequiredArgsConstructor
public class BucketProvider {

    private final ProxyManager<byte[]> proxyManager;

    // BucketConfiguration is immutable and identical for every key under a given
    // policy, so it's built once per policy name rather than on every request.
    private final ConcurrentMap<String, BucketConfiguration> configsByPolicy = new ConcurrentHashMap<>();


    public Bucket resolveBucket(String redisKey, String policyName, RateLimitProperties.LimitConfig limitConfig) {

        return proxyManager.builder().build(redisKey.getBytes(), buildConfiguration(limitConfig));
    }

    private BucketConfiguration buildConfiguration(RateLimitProperties.LimitConfig limitConfig) {
        return BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(limitConfig.getCapacity())
                        .refillIntervally(limitConfig.getCapacity(), limitConfig.getRefill())
                        .build())
                .build();
    }
}
