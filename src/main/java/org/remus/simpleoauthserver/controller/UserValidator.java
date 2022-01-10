package org.remus.simpleoauthserver.controller;

import org.remus.simpleoauthserver.request.LoginForm;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class UserValidator implements Validator {
    @Override
    public boolean supports(Class<?> aClass) {
        return LoginForm.class.equals(aClass);
    }

    @Override
    public void validate(Object o, Errors errors) {
        ValidationUtils.rejectIfEmptyOrWhitespace(errors,"userName","username.not.empty");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors,"password","password.not.empty");
    }
}
