package bdj.hkb.auth_service.ratelimit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class RateLimitKeyResolver {

    private final ObjectMapper objectMapper;

    public String resolveIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public String resolveUserIdentifier(HttpServletRequest request, String fieldName) {
        try {
            byte[] body = request.getInputStream().readAllBytes();
            if (body.length == 0) {
                return null;
            }
            JsonNode node = objectMapper.readTree(body);
            JsonNode field = node.get(fieldName);
            return field != null && !field.isNull() ? field.asText().toLowerCase() : null;
        } catch (IOException e) {
            return null;
        }
    }

    public String buildKey(String prefix, String discriminator) {
        return prefix + ":" + discriminator;
    }
}
