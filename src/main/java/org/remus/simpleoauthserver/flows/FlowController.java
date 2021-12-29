package org.remus.simpleoauthserver.flows;

import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;

import java.util.List;

@Controller
public class FlowController {

    public boolean isClientCredentialFlow(MultiValueMap<String, String> data) {
        String type = String.valueOf(data.toSingleValueMap().get("grant_type"));
        return type != null && "client_credentials".equals(type);

    }

}
