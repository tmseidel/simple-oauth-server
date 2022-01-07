package org.remus.simpleoauthserver;

import org.apache.commons.lang3.RandomUtils;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;

import java.util.HashSet;
import java.util.Set;

public class TestUtils {

    public static Set<Scope> createScope(String name) {
        HashSet<Scope> scopes = new HashSet<>();
        Scope scope = new Scope();
        scope.setName(name);
        scopes.add(scope);
        return scopes;
    }

    public static Organization createOrganization(int id) {
        Organization org = new Organization();
        org.setName("Junit-Org");
        org.setId(id);
        return org;
    }

    public static User createUser(String name, String mail) {
        User user = new User();
        user.setId(RandomUtils.nextInt());
        user.setName(name);
        user.setEmail(mail);
        user.setActivated(true);
        return user;
    }
}
