package bdj.hkb.auth_service.exceptionHandler;

public class EmailNotVerifiedException extends RuntimeException{
    public EmailNotVerifiedException() {
        super();
    }

    public EmailNotVerifiedException(String message) {
        super(message);
    }

    public EmailNotVerifiedException(String message, Throwable cause) {
        super(message, cause);
    }
}
