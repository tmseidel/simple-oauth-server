package org.remus.simpleoauthserver.request;

public class CreateSuperAdminRequest {

    private String superAdminEmail;

    private String superAdminName;

    private String superAdminPassword;

    private String organization;

    private String initialAuthToken;

    public String getSuperAdminEmail() {
        return superAdminEmail;
    }

    public void setSuperAdminEmail(String superAdminEmail) {
        this.superAdminEmail = superAdminEmail;
    }

    public String getSuperAdminPassword() {
        return superAdminPassword;
    }

    public void setSuperAdminPassword(String superAdminPassword) {
        this.superAdminPassword = superAdminPassword;
    }

    public String getInitialAuthToken() {
        return initialAuthToken;
    }

    public void setInitialAuthToken(String initialAuthToken) {
        this.initialAuthToken = initialAuthToken;
    }

    public String getSuperAdminName() {
        return superAdminName;
    }

    public void setSuperAdminName(String superAdminName) {
        this.superAdminName = superAdminName;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }
}
