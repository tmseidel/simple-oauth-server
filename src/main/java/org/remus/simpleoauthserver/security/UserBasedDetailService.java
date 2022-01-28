package org.remus.simpleoauthserver.security;

import org.remus.simpleoauthserver.config.Configuration;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.service.UserNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component(Configuration.BEAN_NAME_USERBASED_DETAILSERVICE)
public class UserBasedDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserBasedDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<User> oneByEmail = userRepository.findOneByEmailAndActivated(s,true);
        User user = oneByEmail.orElseThrow(() -> new UserNotFoundException(String.format("User %s not found",s)));

        return new JWTUser(user);
    }




}
