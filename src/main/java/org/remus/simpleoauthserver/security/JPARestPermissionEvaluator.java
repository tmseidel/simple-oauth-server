/**
 * Copyright(c) 2022 Tom Seidel, Remus Software
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
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
            boolean sameUser = user.getUser().getId().equals(((User) o).getId());
            boolean ownerOfUser = scopeRanking.isOrganizationOwner(scopes) && ((User) o).getOrganization().getId().equals(user.getUser().getOrganization().getId());
            boolean userHasAdminScope = ((User) o).getScopeList().stream().anyMatch(e->ScopeRanking.SUPERADMIN_SCOPE.equals(e.getName()));
            // Restrictions if the user edit his own entity, no scopes, no organization
            boolean restrictionMet = true;
            if (sameUser) {
                boolean scopeIdentical = ((User) o).getScopeList().equals(((User) o).getStoredScopes());
                boolean organizationIdentical = ((User) o).getOrganization().equals(((User) o).getStoredOrganization());
                boolean activatedIdentical = ((User) o).isActivated() == ((User) o).isStoredActivated();
                restrictionMet = scopeIdentical && organizationIdentical && activatedIdentical;
            }
            returnValue = !userHasAdminScope && restrictionMet && (sameUser || ownerOfUser);
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