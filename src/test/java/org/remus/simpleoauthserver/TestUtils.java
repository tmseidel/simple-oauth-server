package org.remus.simpleoauthserver;

import org.apache.commons.lang3.RandomUtils;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;

import java.util.HashSet;
import java.util.Set;

public class TestUtils {

    public static class TestUser {
        private final String userName;
        private final String passWord;
        private final String clientId;
        private final String[] scope;

        public TestUser(String userName, String passWord, String clientId, String... scope) {
            this.userName = userName;
            this.passWord = passWord;
            this.clientId = clientId;
            this.scope = scope;
        }

        public String getUserName() {
            return userName;
        }

        public String getPassWord() {
            return passWord;
        }

        public String getClientId() {
            return clientId;
        }

        public String[] getScope() {
            return scope;
        }
    }



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
