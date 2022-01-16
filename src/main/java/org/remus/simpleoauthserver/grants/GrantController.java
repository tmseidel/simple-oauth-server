package org.remus.simpleoauthserver.grants;

import org.remus.simpleoauthserver.controller.ValueExtractionUtil;
import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.UnsupportedGrantTypeException;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;

import java.util.Set;

import static java.lang.String.format;
import static org.owasp.encoder.Encode.forJava;

/**
 * This controller is used in the Token-Endpoint to decide which Flow is in progress.
 */
@Controller
public class GrantController {

    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    private static final Set<String> VALID_GRANT_TYPES = Set.of(CLIENT_CREDENTIALS, AUTHORIZATION_CODE);

    public boolean isClientCredentialGrant(MultiValueMap<String, String> data) {
        String type = getGrantType(data);
        return CLIENT_CREDENTIALS.equals(type);
    }

    public boolean isAuthorizationGrant(MultiValueMap<String, String> data) {
        String type = getGrantType(data);
        return AUTHORIZATION_CODE.equals(type);
    }

    private String getGrantType(MultiValueMap<String, String> data) {
        String type = ValueExtractionUtil.extractValue(data, "grant_type").orElseThrow(() -> new InvalidInputException("No grant_type present"));
        if (!VALID_GRANT_TYPES.contains(type)) {
            throw new UnsupportedGrantTypeException(format("Grant type %s not supported", forJava(type)));
        }
        return type;
    }

}
