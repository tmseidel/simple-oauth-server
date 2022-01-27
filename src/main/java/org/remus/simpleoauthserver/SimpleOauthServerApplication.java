package org.remus.simpleoauthserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class SimpleOauthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SimpleOauthServerApplication.class, args);
    }

}
