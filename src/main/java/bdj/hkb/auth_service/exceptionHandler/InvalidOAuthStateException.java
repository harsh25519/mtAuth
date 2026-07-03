package bdj.hkb.auth_service.exceptionHandler;

public class InvalidOAuthStateException extends RuntimeException {

    public InvalidOAuthStateException() {
        super();
    }

    public InvalidOAuthStateException(String message) {
        super(message);
    }

    public InvalidOAuthStateException(String message, Throwable cause) {
        super(message, cause);
    }
}
