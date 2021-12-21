package org.remus.simpleoauthserver.service;

public class UserLockedException extends RuntimeException {
    public UserLockedException() {
    }

    public UserLockedException(String message) {
        super(message);
    }

    public UserLockedException(String message, Throwable cause) {
        super(message, cause);
    }

    public UserLockedException(Throwable cause) {
        super(cause);
    }

    public UserLockedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
