package bdj.hkb.auth_service.config;

import bdj.hkb.auth_service.ratelimit.RateLimitProperties;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.Bucket4jLettuce;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.codec.ByteArrayCodec;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.data.redis.autoconfigure.DataRedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class RateLimitRedisConfig {

    @Bean(destroyMethod = "shutdown")
    public RedisClient bucket4jRedisClient(DataRedisProperties properties) {
        RedisURI.Builder builder = RedisURI.Builder.redis(properties.getHost(), properties.getPort());

        // Respect Spring Boot's native Redis security configurations
        if (properties.getPassword() != null && !properties.getPassword().isEmpty()) {
            builder.withPassword(properties.getPassword().toCharArray());
        }
        if (properties.getDatabase() != 0) {
            builder.withDatabase(properties.getDatabase());
        }
        if (properties.getSsl().isEnabled()) {
            builder.withSsl(true);
        }

        return RedisClient.create(builder.build());
    }


    @Bean
    public ProxyManager<byte[]> proxyManager(RedisClient bucket4jRedisClient) {
        return Bucket4jLettuce
                .casBasedBuilder(bucket4jRedisClient.connect(ByteArrayCodec.INSTANCE))
                .build();
    }
}
