package org.remus.simpleoauthserver.security;


import java.util.Set;

public class ScopeRanking {

    public static final String SUPERADMIN_SCOPE = "data.superadmin";

    public static final String ORGANIZATION_OWNER_SCOPE = "data.orgowner";

    public boolean isSuperAdmin(Set<String> scopes) {
        return scopes.contains(SUPERADMIN_SCOPE);
    }

    public boolean isOrganizationOwner(Set<String> scopes) {
        return scopes.contains(SUPERADMIN_SCOPE) || scopes.contains(ORGANIZATION_OWNER_SCOPE);
    }

}
