package bdj.hkb.auth_service.exceptionHandler;

public class SelfLockoutException extends RuntimeException{
    public SelfLockoutException() {
        super();
    }

    public SelfLockoutException(String message) {
        super(message);
    }

    public SelfLockoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
