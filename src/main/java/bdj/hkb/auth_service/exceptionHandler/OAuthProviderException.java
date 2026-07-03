package bdj.hkb.auth_service.exceptionHandler;

public class OAuthProviderException extends RuntimeException{
    public OAuthProviderException() {
        super();
    }

    public OAuthProviderException(String message) {
        super(message);
    }

    public OAuthProviderException(String message, Throwable cause) {
        super(message, cause);
    }
}
