package bdj.hkb.auth_service.exceptionHandler;

public class InvalidEmailVerificationTokenException extends RuntimeException{
    public InvalidEmailVerificationTokenException() {
        super();
    }

    public InvalidEmailVerificationTokenException(String message) {
        super(message);
    }

    public InvalidEmailVerificationTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
