package org.remus.simpleoauthserver.entity.projection;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.springframework.data.rest.core.config.Projection;

import java.util.Set;

@Projection(name = "configclient", types= Application.class)
public interface ApplicationProjection {
    Integer getId();

    String getName();

    String getClientId();

    Set<String> getLoginUrls();

    String getLogoutUrl();

    String getCss();

    boolean isActivated();

    String getClientSecret();

    Set<Scope> getScopeList();

    ApplicationType getApplicationType();

    boolean isTrustworthy();

}
