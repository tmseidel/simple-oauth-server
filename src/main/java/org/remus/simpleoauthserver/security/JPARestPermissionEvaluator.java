package org.remus.simpleoauthserver.security;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This permission evaluator checks the permissions on JPA Layer
 */
public class JPARestPermissionEvaluator implements PermissionEvaluator {

    public static final String READ = "read";
    public static final String WRITE = "write";
    public static final String DELETE = "delete";

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private ScopeRanking scopeRanking = new ScopeRanking();

    @Override
    public boolean hasPermission(
            Authentication auth, Object targetDomainObject, Object permission) {
        if ((auth == null) || (targetDomainObject == null) || !(permission instanceof String)) {
            return false;
        }

        JWTUser user = (JWTUser) auth.getPrincipal();
        if (logger.isDebugEnabled()) {
            logger.debug("hasPermission: User {} with permission {} on object {}", user.getUser(), permission, targetDomainObject);
        }
        Set<String> scopes = user.getAuthorities().stream().map(e -> ((GrantedAuthority) e).getAuthority()).collect(Collectors.toSet());
        if (scopeRanking.isSuperAdmin(scopes)) {
            // If the user has the data-admin
            return true;
        }
        Iterable<?> iterable = extractTargetObject(targetDomainObject);
        for (Object o : iterable) {
            boolean returnValue = true;
            if (o == null) {
                returnValue = false;
            }
            returnValue = checkUser(user, scopes, o, returnValue);
            returnValue = checkOrganization(user, scopes, o, returnValue);
            returnValue = checkScope(permission, o, returnValue);
            returnValue = checkApplication(permission, o, returnValue);
            if (!returnValue) {
                logger.warn("Permission denied for {} on {} with user {}", o, permission, user);
                return false;
            }
        }
        return true;
    }

    protected boolean checkApplication(Object permission, Object o, boolean returnValue) {
        if (o instanceof Application) {
            returnValue = READ.equals(permission);
        }
        return returnValue;
    }

    /**
     * Scopes can only be edited by {@link ScopeRanking#SUPERADMIN_SCOPE}.
     * @param permission
     * @param o
     * @param returnValue
     * @return
     */
    protected boolean checkScope(Object permission, Object o, boolean returnValue) {
        if (o instanceof Scope) {
            returnValue = READ.equals(permission);
        }
        return returnValue;
    }

    protected boolean checkOrganization(JWTUser user, Set<String> scopes, Object o, boolean returnValue) {
        if (o instanceof Organization) {
            returnValue = scopeRanking.isOrganizationOwner(scopes) && user.getUser().getOrganization().getId().equals(((Organization) o).getId());
        }
        return returnValue;
    }

    protected boolean checkUser(JWTUser user, Set<String> scopes, Object o, boolean returnValue) {
        if (o instanceof User) {
            boolean allowed = scopeRanking.isOrganizationOwner(scopes);
            // The user has only the right to see his user from the same organization
            returnValue = allowed;
            if (allowed) {
                returnValue = user.getUser().getId().equals(((User) o).getId()) || ((User) o).getOrganization().getId().equals(user.getUser().getOrganization().getId());
            }
        }
        return returnValue;
    }

    private Iterable<?> extractTargetObject(Object source) {
        if (source instanceof Iterable) {
            return (Iterable) source;
        } else if (source instanceof Optional) {
            return Collections.singletonList(((Optional) source).orElse(null));
        } else {
            return Collections.singletonList(source);
        }
    }

    @Override
    public boolean hasPermission(
            Authentication auth, Serializable targetId, String targetType, Object permission) {
        if ((auth == null) || (targetType == null) || !(permission instanceof String)) {
            return false;
        }
        return hasPrivilege(auth, targetType.toUpperCase(),
                permission.toString().toUpperCase());
    }

    private boolean hasPrivilege(Authentication auth, String targetType, String permission) {
        for (GrantedAuthority grantedAuth : auth.getAuthorities()) {
            if (grantedAuth.getAuthority().startsWith(targetType)
                    && grantedAuth.getAuthority().contains(permission)) {
                return true;
            }
        }
        return false;
    }
}