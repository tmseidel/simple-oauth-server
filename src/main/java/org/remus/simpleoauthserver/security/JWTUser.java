package org.remus.simpleoauthserver.security;

import org.remus.simpleoauthserver.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class JWTUser implements UserDetails {

        private final Set<SimpleGrantedAuthority> authorities;
        private transient User user;

        public JWTUser(User user) {
            this.user = user;
            this.authorities = user.getScopeList().stream().map(e -> new SimpleGrantedAuthority(e.getName())).collect(Collectors.toSet());
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return this.authorities;
        }

        @Override
        public String getPassword() {
            return user.getPassword();
        }

        @Override
        public String getUsername() {
            return user.getEmail();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return false;
        }

        @Override
        public boolean isEnabled() {
            return user.isActivated();
        }

    public User getUser() {
        return user;
    }
}