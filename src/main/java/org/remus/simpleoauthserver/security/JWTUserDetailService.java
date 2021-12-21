package org.remus.simpleoauthserver.security;

import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.repository.UserRepository;
import org.remus.simpleoauthserver.service.UserNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component("jwtuserdetailservice")
public class JWTUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public JWTUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<User> oneByEmail = userRepository.findOneByEmailAndActivated(s,true);
        User user = oneByEmail.orElseThrow(() -> new UserNotFoundException("User not found"));

        return new JWTUser(user);
    }




}
