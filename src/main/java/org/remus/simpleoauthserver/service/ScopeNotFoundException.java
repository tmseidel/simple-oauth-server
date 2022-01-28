package org.remus.simpleoauthserver.service;

public class ScopeNotFoundException extends RuntimeException {
    public ScopeNotFoundException(String s) {
        super(s);
    }
}
