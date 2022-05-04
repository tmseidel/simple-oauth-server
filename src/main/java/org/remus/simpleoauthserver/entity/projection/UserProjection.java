package org.remus.simpleoauthserver.entity.projection;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.springframework.data.rest.core.config.Projection;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Projection(name = "configclient", types= User.class)
public interface UserProjection {
    Integer getId();

    String getName();

    String getEmail();

    boolean isActivated();

    Date getLastLogin();

    Date getCreated();

    Set<Scope> getScopeList();

    List<Application> getApplications();

    Organization getOrganization();

    Map<String, String> getProperties();


}
