package org.remus.simpleoauthserver.service;

public class InvalidGrandException extends OAuthException {

    public InvalidGrandException() {
    }

    public InvalidGrandException(String message) {
        super(message);
    }

    public InvalidGrandException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidGrandException(Throwable cause) {
        super(cause);
    }

    public InvalidGrandException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
