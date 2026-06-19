package bdj.hkb.auth_service.exceptionHandler;

import java.time.OffsetDateTime;

public record ErrorResponse(
        int statusCode,
        String message,
        OffsetDateTime timestamp
) {
}
