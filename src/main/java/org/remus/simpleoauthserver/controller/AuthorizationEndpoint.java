/**
 * Copyright(c) 2022 Tom Seidel, Remus Software
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.remus.simpleoauthserver.controller;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.grants.AuthorizationGrant;
import org.remus.simpleoauthserver.request.AuthorizeApplicationForm;
import org.remus.simpleoauthserver.request.LoginForm;
import org.remus.simpleoauthserver.response.ErrorResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.InvalidIpException;
import org.remus.simpleoauthserver.service.LoginAttemptService;
import org.remus.simpleoauthserver.service.OAuthException;
import org.remus.simpleoauthserver.service.ScopeNotFoundException;
import org.remus.simpleoauthserver.service.TokenHelper;
import org.remus.simpleoauthserver.service.UserLockedException;
import org.remus.simpleoauthserver.service.UserNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;
import static org.remus.simpleoauthserver.grants.OAuthGrant.CODE_CHALLENGE;

@Controller
@RequestMapping(path = "/auth/oauth")
public class AuthorizationEndpoint {

    public static final String STATE = "state";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String USER_NAME = "userName";
    public static final String CLIENT_ID = "client_id";
    public static final String SCOPE = "scope";

    private final LoginAttemptService loginAttemptService;

    private final UserValidator userValidator;

    private final AuthorizationGrant authFlow;

    private final TokenHelper tokenHelper;



    public AuthorizationEndpoint(UserValidator userValidator, LoginAttemptService loginAttemptService, AuthorizationGrant authFlow, TokenHelper tokenHelper) {
        this.userValidator = userValidator;
        this.loginAttemptService = loginAttemptService;
        this.authFlow = authFlow;
        this.tokenHelper = tokenHelper;
    }

    @InitBinder("login")
    protected void initBinder(WebDataBinder binder) {
        binder.addValidators(userValidator);
    }

    @GetMapping("/authorize")
    public String authorize(@RequestParam MultiValueMap<String, String> requestParams,
                            Model model, HttpSession session) {
        authFlow.validateAuthorizationRequest(requestParams);
        Application application = authFlow.findApplication(requestParams);
        Map<String,Object> values = new HashMap<>();
        values.put(STATE, extractValue(requestParams,STATE).orElse(null));
        values.put(CLIENT_ID, extractValue(requestParams, CLIENT_ID).orElseThrow());
        values.put(SCOPE, extractValue(requestParams, SCOPE).orElse(null));
        values.put(CODE_CHALLENGE, extractValue(requestParams, CODE_CHALLENGE).orElse(null));
        values.put(REDIRECT_URI,  extractValue(requestParams,REDIRECT_URI).orElse(null));
        model.addAttribute("login", new LoginForm(tokenHelper.encode(values)));
        model.addAttribute("appName", application.getName());
        model.addAttribute("appCss", application.getCss());

        return "authorize";
    }

    @PostMapping("/authorize")
    public String authorizeSubmit(@ModelAttribute("login") @Validated LoginForm login, BindingResult result,
                                  Model model, RedirectAttributes redirectAttributes, HttpServletRequest request) {
        String token = login.getSignedData();
        Map<String, Object> values = tokenHelper.decode(token, REDIRECT_URI, CLIENT_ID, SCOPE, STATE, CODE_CHALLENGE);
        String redirectUri = (String) values.get(REDIRECT_URI);
        String clientId = (String) values.get(CLIENT_ID);
        String scopeList = (String) values.get(SCOPE);
        String state = (String) values.get(STATE);
        String codeChallenge = (String) values.get(CODE_CHALLENGE);
        if (loginAttemptService.isBlocked(request.getRemoteAddr())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "This IP is blocked");
        }
        Application application = authFlow.getApplicationByClientIdAndRedirect(clientId, redirectUri);
        model.addAttribute("login", login);
        model.addAttribute("appName", application.getName());
        model.addAttribute("appCss", application.getCss());
        if (!result.hasErrors()) {
            try {
                User user = authFlow.checkLogin(login.getUserName(), login.getPassword(), clientId, request.getRemoteAddr(), scopeList.split(","));
                loginAttemptService.loginSucceeded(request.getRemoteAddr());
                if (authFlow.needsUserPermissionForApp(user, clientId)) {
                    values.put("user", user.getEmail());
                    model.addAttribute("registerApp", new AuthorizeApplicationForm(tokenHelper.encode(values)));
                    return "registerapp";
                } else {
                    String authorizationToken = authFlow.createAuthorizationToken(login.getUserName(), values);
                    redirectAttributes.addAttribute("code", authorizationToken);
                    redirectAttributes.addAttribute(STATE, state);
                    authFlow.checkPkceEntry(codeChallenge,authorizationToken,clientId,redirectUri);
                    return "redirect:" + redirectUri;
                }
            } catch (UserNotFoundException e) {
                result.rejectValue(USER_NAME, "user.not.found");
                loginAttemptService.loginFailed(request.getRemoteAddr());
            } catch (InvalidIpException e) {
                result.rejectValue(USER_NAME, "user.ip.not.allowed");
            } catch (UserLockedException e) {
                result.rejectValue(USER_NAME, "user.locked");
            } catch (ScopeNotFoundException e) {
                result.rejectValue(USER_NAME, "scope.not.found");
                redirectAttributes.addAttribute("error.id", "invalid_scope");
                redirectAttributes.addAttribute("error.message", "The user has cancelled the login");
                redirectAttributes.addAttribute(STATE,state);
                RedirectView redirectView = new RedirectView();
                redirectView.setUrl(redirectUri);
            }
        }
        return "authorize";
    }


    @PostMapping("/registerApp")
    public String registerApplication(@ModelAttribute("registerApp") AuthorizeApplicationForm form,
                                      Model model, RedirectAttributes redirectAttributes) {
        Map<String, Object> data = tokenHelper.decode(form.getSignedData(), REDIRECT_URI, "user", STATE, CLIENT_ID);
        String redirectUri = (String) data.get(REDIRECT_URI);
        String userName = (String) data.get("user");
        String clientId = (String) data.get(CLIENT_ID);
        String state = (String) data.get(STATE);
        String codeChallenge = (String) data.get(CODE_CHALLENGE);
        authFlow.registerApplication(clientId,userName);
        String authorizationToken = authFlow.createAuthorizationToken(userName, data);
        redirectAttributes.addAttribute("code", authorizationToken);
        redirectAttributes.addAttribute(STATE,state);
        authFlow.checkPkceEntry(codeChallenge,authorizationToken,clientId,redirectUri);
        return "redirect:" + redirectUri;
    }

    @PostMapping("/cancelLogin")
    public RedirectView cancelSubmit(@ModelAttribute("login") LoginForm loginForm, RedirectAttributes redirectAttributes) {
        Map<String, Object> values = tokenHelper.decode(loginForm.getSignedData(), REDIRECT_URI, STATE);
        String redirectUri = (String) values.get(REDIRECT_URI);
        String state = (String) values.get(STATE);
        redirectAttributes.addAttribute("error.id", "user.cancelled");
        redirectAttributes.addAttribute("error.message", "The user has cancelled the login");
        redirectAttributes.addAttribute(STATE,state);
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl(redirectUri);
        return redirectView;

    }

    @ResponseBody
    @ExceptionHandler({OAuthException.class, ApplicationNotFoundException.class})
    public ResponseEntity<ErrorResponse> handleUnsupportedGrantTypeException(HttpServletRequest request, Throwable ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(new ErrorResponse("invalid_client", ex.getMessage()), status);
    }
}
