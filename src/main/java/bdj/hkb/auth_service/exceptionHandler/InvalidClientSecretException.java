package bdj.hkb.auth_service.exceptionHandler;

public class InvalidClientSecretException extends RuntimeException{
    public InvalidClientSecretException() {
        super();
    }

    public InvalidClientSecretException(String message) {
        super(message);
    }

    public InvalidClientSecretException(String message, Throwable cause) {
        super(message, cause);
    }
}
