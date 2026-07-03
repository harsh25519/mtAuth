package bdj.hkb.auth_service.exceptionHandler;

public class OAuthCodeSerializationException extends RuntimeException{
    public OAuthCodeSerializationException() {
        super();
    }

    public OAuthCodeSerializationException(String message) {
        super(message);
    }

    public OAuthCodeSerializationException(String message, Throwable cause) {
        super(message, cause);
    }
}
