package org.remus.simpleoauthserver;

import org.remus.simpleoauthserver.security.ScopeRanking;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.ClientCredentialsGrant;
import springfox.documentation.service.GrantType;
import springfox.documentation.service.OAuth;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.data.rest.configuration.SpringDataRestConfiguration;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Configuration
@Import(SpringDataRestConfiguration.class)
public class SpringFoxConfig {


    @Value("${swagger.oauth.api.title}")
    private String apiName;

    @Value("${swagger.oauth.api.url}")
    private String apiUrl;

    @Value("${swagger.oauth.api.oauthendpoint}")
    private String oauthEndpoint;


    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.ant("/auth/admin/data/**"))
                .build().protocols(Set.of("http", "https")).securitySchemes(Collections.singletonList(securitySchema()))
                .securityContexts(Collections.singletonList(securityContext())).pathMapping("/")
                .useDefaultResponseMessages(false).apiInfo(apiInfo());
    }

    private OAuth securitySchema() {

        List<AuthorizationScope> authorizationScopeList = new ArrayList<>();
        authorizationScopeList.add(new AuthorizationScope(ScopeRanking.SUPERADMIN_SCOPE, "read/write all"));

        List<GrantType> grantTypes = new ArrayList<>();

        GrantType creGrant = new ClientCredentialsGrant(oauthEndpoint);

        grantTypes.add(creGrant);

        return new OAuth("oauth2schema", authorizationScopeList, grantTypes);

    }


    private ApiInfo apiInfo() {
        return new ApiInfoBuilder().title(apiName).description("")
                .termsOfServiceUrl(apiUrl)
                .build();
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder().securityReferences(defaultAuth()).operationSelector(e -> e.requestMappingPattern().startsWith("/auth/admin/data/"))
                .build();
    }

    private List<SecurityReference> defaultAuth() {
        final AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = new AuthorizationScope(ScopeRanking.SUPERADMIN_SCOPE, "read all");
        return Collections.singletonList(new SecurityReference("oauth2schema", authorizationScopes));
    }
}