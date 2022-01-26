package org.remus.simpleoauthserver;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.Organization;
import org.remus.simpleoauthserver.entity.Scope;
import org.remus.simpleoauthserver.entity.User;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;

@org.springframework.context.annotation.Configuration
public class Configuration {

    public static final String BEAN_NAME_USERBASED_DETAILSERVICE = "userbaseddetailservice";
    public static final String BEAN_NAME_APPBASED_DETAILSERVICE = "appbaseddetailservice";


    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public RepositoryRestConfigurer repositoryRestConfigurer() {

        return new RepositoryRestConfigurer() {
            @Override
            public void configureRepositoryRestConfiguration(RepositoryRestConfiguration config, CorsRegistry cors) {
                config.exposeIdsFor(User.class, Application.class, Scope.class, Organization.class);
                cors.addMapping("/*")
                        .allowedOrigins("*")
                        .allowedMethods("GET", "PUT", "DELETE", "PATCH")
                        .allowCredentials(false).maxAge(3600);
            }

        };

    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ErrorAttributes errorAttributes() {
        return new DefaultErrorAttributes() {

            @Override
            public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
                Map<String, Object> errorAttributes
                        = super.getErrorAttributes(webRequest, options);
                errorAttributes.remove("message");
                return errorAttributes;
            }
        };
    }

    @Bean
    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasenames("i18n/messages");
        source.setUseCodeAsDefaultMessage(true);
        return source;
    }

}
