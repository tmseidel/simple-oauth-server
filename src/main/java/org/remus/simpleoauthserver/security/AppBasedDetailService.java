package org.remus.simpleoauthserver.security;

import org.remus.simpleoauthserver.Configuration;
import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.ApplicationRepository;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component(Configuration.BEAN_NAME_APPBASED_DETAILSERVICE)
public class AppBasedDetailService implements UserDetailsService {
    private ApplicationRepository applicationRepository;

    public AppBasedDetailService(ApplicationRepository applicationRepository) {
        this.applicationRepository = applicationRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Application application = applicationRepository.findApplicationByClientId(s).orElseThrow(() -> new ApplicationNotFoundException(String.format("Application %s not found", s)));
        User syntheticApplicationUser = new User();
        syntheticApplicationUser.setId(Integer.MAX_VALUE);
        syntheticApplicationUser.setScopeList(Set.of(application.getScopeList().toArray(new Scope[0])));
        syntheticApplicationUser.setName(s);

        return new JWTUser(syntheticApplicationUser);
    }
}
