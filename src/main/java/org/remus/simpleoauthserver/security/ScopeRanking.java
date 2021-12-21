package org.remus.simpleoauthserver.security;


import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;

import java.util.List;
import java.util.Set;

public class ScopeRanking {

    public static final String SUPERADMIN_SCOPE = "data.superadmin";

    public static final String ORGANIZATION_OWNER_SCOPE = "data.orgowner";

    public static final String MONITORING_SCOPE = "data.monitoring";

    public static final List<String> PREDEFINED_SCOPES = List.of(SUPERADMIN_SCOPE,ORGANIZATION_OWNER_SCOPE,MONITORING_SCOPE);


    public boolean isSuperAdmin(Set<String> scopes) {
        return scopes.contains(SUPERADMIN_SCOPE);
    }

    public boolean isOrganizationOwner(Set<String> scopes) {
        return scopes.contains(SUPERADMIN_SCOPE) || scopes.contains(ORGANIZATION_OWNER_SCOPE);
    }

}
