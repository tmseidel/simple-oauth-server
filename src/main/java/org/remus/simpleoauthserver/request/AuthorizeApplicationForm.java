package org.remus.simpleoauthserver.request;

public class AuthorizeApplicationForm {

    private String signedData;

    public AuthorizeApplicationForm(String signedData) {
        this.signedData = signedData;
    }

    public String getSignedData() {
        return signedData;
    }

    public void setSignedData(String signedData) {
        this.signedData = signedData;
    }
}
