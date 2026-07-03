package bdj.hkb.auth_service.exceptionHandler;

public class InvalidPasswordResetTokenException extends RuntimeException{
    public InvalidPasswordResetTokenException() {
        super();
    }

    public InvalidPasswordResetTokenException(String message) {
        super(message);
    }

    public InvalidPasswordResetTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
