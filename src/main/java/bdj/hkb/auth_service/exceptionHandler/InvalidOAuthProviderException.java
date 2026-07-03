package bdj.hkb.auth_service.exceptionHandler;

public class InvalidOAuthProviderException extends RuntimeException{
    public InvalidOAuthProviderException() {
        super();
    }

    public InvalidOAuthProviderException(String message) {
        super(message);
    }

    public InvalidOAuthProviderException(String message, Throwable cause) {
        super(message, cause);
    }
}
