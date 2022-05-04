package org.remus.simpleoauthserver.service;

public class PkceFailedException extends OAuthException {
    public PkceFailedException() {
        super();
    }

    public PkceFailedException(String message) {
        super(message);
    }

    public PkceFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public PkceFailedException(Throwable cause) {
        super(cause);
    }

    protected PkceFailedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
