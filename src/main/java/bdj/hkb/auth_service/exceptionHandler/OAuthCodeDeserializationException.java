package bdj.hkb.auth_service.exceptionHandler;

public class OAuthCodeDeserializationException extends RuntimeException{
    public OAuthCodeDeserializationException() {
        super();
    }

    public OAuthCodeDeserializationException(String message) {
        super(message);
    }

    public OAuthCodeDeserializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
