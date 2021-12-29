package org.remus.simpleoauthserver;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.security.ScopeRanking;

import java.util.Collections;

public class TestUtils {

    public static Scope createScope(String name) {
        Scope scope = new Scope();
        scope.setName(name);
        return scope;
    }

    public static Organization createOrganization(int id) {
        Organization org = new Organization();
        org.setName("Junit-Org");
        org.setId(id);
        return org;
    }

    public static User createUser(String name,String mail) {
        User user = new User();
        user.setId(RandomUtils.nextInt());
        user.setName(name);
        user.setEmail(mail);
        user.setActivated(true);
        return user;
    }
}
