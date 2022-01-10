package org.remus.simpleoauthserver.controller;

import org.springframework.util.MultiValueMap;

import java.util.Optional;

public class ValueExtractionUtil {

    private ValueExtractionUtil() {
        // prevents instantiation
    }

    public static Optional<String> extractValue(MultiValueMap<String,String> data, String key) {
        String value = data.getFirst(key);
        return value == null ? Optional.empty() : Optional.of(value);
    }
}
