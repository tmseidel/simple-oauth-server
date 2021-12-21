package org.remus.simpleoauthserver.service;

public class InvalidIpException extends RuntimeException {
    public InvalidIpException() {
        super();
    }

    public InvalidIpException(String message) {
        super(message);
    }

    public InvalidIpException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidIpException(Throwable cause) {
        super(cause);
    }

    protected InvalidIpException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
