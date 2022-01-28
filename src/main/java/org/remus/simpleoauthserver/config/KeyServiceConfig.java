package org.remus.simpleoauthserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix="soas.keyservice")
public class KeyServiceConfig {

    private String basePath;

    private String privateKeyLocation;

    private String publicKeyLocation;

    private String jwtKeysLocation;

    public String getBasePath() {
        return basePath;
    }

    public void setBasePath(String basePath) {
        this.basePath = basePath;
    }

    public String getPrivateKeyLocation() {
        return privateKeyLocation;
    }

    public void setPrivateKeyLocation(String privateKeyLocation) {
        this.privateKeyLocation = privateKeyLocation;
    }

    public String getPublicKeyLocation() {
        return publicKeyLocation;
    }

    public void setPublicKeyLocation(String publicKeyLocation) {
        this.publicKeyLocation = publicKeyLocation;
    }

    public String getJwtKeysLocation() {
        return jwtKeysLocation;
    }

    public void setJwtKeysLocation(String jwtKeysLocation) {
        this.jwtKeysLocation = jwtKeysLocation;
    }
}
