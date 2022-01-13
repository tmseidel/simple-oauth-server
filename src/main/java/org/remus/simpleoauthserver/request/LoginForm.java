package org.remus.simpleoauthserver.request;

public class LoginForm {

    private String userName;

    private String password;

    private String signedData;

    public LoginForm(String signedData) {
        this.signedData = signedData;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSignedData() {
        return signedData;
    }

    public void setSignedData(String signedData) {
        this.signedData = signedData;
    }
}
