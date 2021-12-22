package org.remus.simpleoauthserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;

import javax.inject.Inject;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Inject
    private JwtAuthorizationTokenFilter filter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {


        http.csrf().disable()
                .cors()
                .and()
                .exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/auth/css/**").permitAll()
                .antMatchers(HttpMethod.GET,"/auth/oauth2/**").permitAll()
                .antMatchers(HttpMethod.POST,"/auth/oauth2/**").permitAll()
                .antMatchers(HttpMethod.GET,"/auth/firstStart/**").permitAll()
                .antMatchers(HttpMethod.POST,"/auth/firstStart/**").permitAll()
                .antMatchers(HttpMethod.POST,"/auth/api/**").authenticated()
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                .antMatchers(HttpMethod.GET, "/auth/admin/**").hasAnyAuthority("data.admin","dispatch.admin")
                .antMatchers(HttpMethod.POST, "/auth/admin/**").hasAnyAuthority("data.admin","dispatch.admin")
                .antMatchers(HttpMethod.PUT, "/auth/admin/**").hasAnyAuthority("data.admin","dispatch.admin")
                .antMatchers(HttpMethod.DELETE, "/auth/admin/**").hasAnyAuthority("data.admin","dispatch.admin")
                .antMatchers(HttpMethod.PATCH, "/auth/admin/**").hasAnyAuthority("data.admin","dispatch.admin")
                .antMatchers(HttpMethod.GET, "/auth/errors/**").permitAll()
                .anyRequest().authenticated();

        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public HttpFirewall allowUrlEncodedSlashHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedPercent(true);;
        firewall.setAllowSemicolon(true);
        return firewall;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        // @formatter:off
        web.httpFirewall(allowUrlEncodedSlashHttpFirewall());
    }

}
