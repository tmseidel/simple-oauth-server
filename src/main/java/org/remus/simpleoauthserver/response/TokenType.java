package org.remus.simpleoauthserver.response;

public enum TokenType {
    BEARER("Bearer");

    private final String stringValue;

    TokenType(String bearer) {
        this.stringValue = bearer;
    }

    public String getStringValue() {
        return stringValue;
    }


}
