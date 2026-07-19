package bdj.hkb.auth_service.ratelimit;

import bdj.hkb.auth_service.exceptionHandler.TooManyRequestsException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Order(1)
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final RateLimitKeyResolver keyResolver;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        RateLimitPolicy policy = RateLimitPolicy.resolve(request.getRequestURI(), request.getMethod());
        if (policy == null) {
            filterChain.doFilter(request, response);
            return;
        }

        CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request);

        try {
            String userIdentifier = keyResolver.resolveUserIdentifier(wrappedRequest, "email");
            rateLimitService.checkAndConsume(policy, wrappedRequest, userIdentifier);
            filterChain.doFilter(wrappedRequest, response);
        } catch (TooManyRequestsException ex) {
            writeRejection(response, ex.getRetryAfterSeconds());
        }
    }

    private void writeRejection(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", 429);
        body.put("error", "Too Many Requests");
        body.put("message", "Too many attempts. Please try again later.");
        body.put("retryAfter", retryAfterSeconds);

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
