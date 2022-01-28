package org.remus.simpleoauthserver.request;

public class InitialApplicationRequest {

    public String getInitialAuthToken() {
        return initialAuthToken;
    }

    public void setInitialAuthToken(String initialAuthToken) {
        this.initialAuthToken = initialAuthToken;
    }

    private String initialAuthToken;


}
