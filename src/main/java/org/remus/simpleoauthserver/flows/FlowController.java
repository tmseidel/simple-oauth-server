package org.remus.simpleoauthserver.flows;

import org.remus.simpleoauthserver.service.InvalidInputException;
import org.remus.simpleoauthserver.service.UnsupportedGrantTypeException;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;

import java.util.Optional;
import java.util.Set;

import static java.lang.String.format;
import static org.owasp.encoder.Encode.forJava;

/**
 * This controller is used in the Token-Endpoint to decide which Flow is in progress.
 */
@Controller
public class FlowController {

    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    private static final Set<String> VALID_GRANT_TYPES = Set.of(CLIENT_CREDENTIALS, AUTHORIZATION_CODE);

    public boolean isClientCredentialFlow(MultiValueMap<String, String> data) {
        String type = getGrantType(data);
        return type != null && CLIENT_CREDENTIALS.equals(type);
    }

    public boolean isAuthorizationFlow(MultiValueMap<String, String> data) {
        String type = getGrantType(data);
        return type != null && AUTHORIZATION_CODE.equals(type);
    }

    private String getGrantType(MultiValueMap<String, String> data) {
        String type = extractValue(data, "grant_type").orElseThrow(() -> new InvalidInputException("No grant_type present"));
        if (!VALID_GRANT_TYPES.contains(type)) {
            throw new UnsupportedGrantTypeException(format("Grant type %s not supported", forJava(type)));
        }
        return type;
    }

    public static Optional<String> extractValue(MultiValueMap<String,String> data, String key) {
        String value = data.getFirst(key);
        return value == null ? Optional.empty() : Optional.of(value);
    }

}
