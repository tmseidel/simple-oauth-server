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
    public static final String AUTH_ADMIN_DATA = "/auth/admin/data/**";
    public static final String AUTH_FIRST_START = "/auth/firstStart/**";
    public static final String AUTH_OAUTH = "/auth/oauth/**";
    public static final String AUTH_CSS = "/auth/css/**";
    public static final String AUTH_API = "/auth/api/**";
    public static final String AUTH_SWAGGER = "/auth/swagger/**";
    public static final String AUTH_ERRORS = "/auth/errors/**";
    @Inject
    private JwtAuthorizationTokenFilter filter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {


        http.csrf().ignoringAntMatchers(AUTH_ADMIN_DATA, AUTH_FIRST_START,"/auth/oauth/token").and()
                .cors()
                .and()
                .exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, AUTH_CSS).permitAll()
                .antMatchers(HttpMethod.GET, AUTH_OAUTH).permitAll()
                .antMatchers(HttpMethod.POST, AUTH_OAUTH).permitAll()
                .antMatchers(HttpMethod.GET, AUTH_FIRST_START).permitAll()
                .antMatchers(HttpMethod.POST, AUTH_FIRST_START).permitAll()
                .antMatchers(HttpMethod.GET, AUTH_SWAGGER).permitAll()
                .antMatchers(HttpMethod.POST, AUTH_API).authenticated()
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                .antMatchers(HttpMethod.GET, AUTH_ADMIN_DATA).hasAnyAuthority(ScopeRanking.SUPERADMIN_SCOPE, ScopeRanking.ORGANIZATION_OWNER_SCOPE)
                .antMatchers(HttpMethod.POST, AUTH_ADMIN_DATA).hasAnyAuthority(ScopeRanking.SUPERADMIN_SCOPE, ScopeRanking.ORGANIZATION_OWNER_SCOPE)
                .antMatchers(HttpMethod.PUT, AUTH_ADMIN_DATA).hasAnyAuthority(ScopeRanking.SUPERADMIN_SCOPE, ScopeRanking.ORGANIZATION_OWNER_SCOPE)
                .antMatchers(HttpMethod.DELETE, AUTH_ADMIN_DATA).hasAnyAuthority(ScopeRanking.SUPERADMIN_SCOPE, ScopeRanking.ORGANIZATION_OWNER_SCOPE)
                .antMatchers(HttpMethod.PATCH, AUTH_ADMIN_DATA).hasAnyAuthority(ScopeRanking.SUPERADMIN_SCOPE, ScopeRanking.ORGANIZATION_OWNER_SCOPE)
                .antMatchers(HttpMethod.GET, AUTH_ERRORS).permitAll()
                .anyRequest().authenticated();

        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public HttpFirewall allowUrlEncodedSlashHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedPercent(true);
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
