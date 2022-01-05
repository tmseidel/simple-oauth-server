package org.remus.simpleoauthserver.service;

public class UnsupportedGrantTypeException extends RuntimeException {

    public UnsupportedGrantTypeException() {
    }

    public UnsupportedGrantTypeException(String message) {
        super(message);
    }

    public UnsupportedGrantTypeException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnsupportedGrantTypeException(Throwable cause) {
        super(cause);
    }

    public UnsupportedGrantTypeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
