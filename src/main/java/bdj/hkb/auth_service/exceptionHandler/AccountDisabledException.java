package bdj.hkb.auth_service.exceptionHandler;

public class AccountDisabledException extends RuntimeException{
    public AccountDisabledException() {
        super();
    }

    public AccountDisabledException(String message) {
        super(message);
    }

    public AccountDisabledException(String message, Throwable cause) {
        super(message, cause);
    }
}
