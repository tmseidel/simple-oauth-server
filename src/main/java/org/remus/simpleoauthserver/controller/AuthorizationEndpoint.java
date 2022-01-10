package org.remus.simpleoauthserver.controller;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.entity.User;
import org.remus.simpleoauthserver.flows.AuthorizationFlow;
import org.remus.simpleoauthserver.request.LoginForm;
import org.remus.simpleoauthserver.response.ErrorResponse;
import org.remus.simpleoauthserver.service.ApplicationNotFoundException;
import org.remus.simpleoauthserver.service.InvalidIpException;
import org.remus.simpleoauthserver.service.LoginAttemptService;
import org.remus.simpleoauthserver.service.OAuthException;
import org.remus.simpleoauthserver.service.ScopeNotFoundException;
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

import static org.remus.simpleoauthserver.controller.ValueExtractionUtil.extractValue;

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

    private final AuthorizationFlow authFlow;


    public AuthorizationEndpoint(UserValidator userValidator, LoginAttemptService loginAttemptService, AuthorizationFlow authFlow) {
        this.userValidator = userValidator;
        this.loginAttemptService = loginAttemptService;
        this.authFlow = authFlow;
    }

    @InitBinder
    protected void initBinder(WebDataBinder binder) {
        binder.addValidators(userValidator);
    }

    @GetMapping("/authorize")
    public String authorize(@RequestParam MultiValueMap<String, String> requestParams,
                            Model model, HttpSession session) {
        authFlow.validateAuthorizationRequest(requestParams);
        Application application = authFlow.findApplication(requestParams);
        model.addAttribute("login", new LoginForm());
        model.addAttribute("appName", application.getName());
        model.addAttribute("appCss", application.getCss());
        session.setAttribute(STATE, extractValue(requestParams,STATE).orElse(null));
        session.setAttribute(CLIENT_ID, extractValue(requestParams, CLIENT_ID).orElseThrow());
        session.setAttribute(SCOPE, extractValue(requestParams, SCOPE).orElse(null));
        session.setAttribute(REDIRECT_URI,  extractValue(requestParams,REDIRECT_URI).orElse(null));
        return "authorize";
    }

    @PostMapping("/authorize")
    public String authorizeSubmit(@ModelAttribute("login") @Validated LoginForm login, BindingResult result,
                                  Model model, RedirectAttributes redirectAttributes, HttpSession session, HttpServletRequest request) {
        String redirectUri = (String) session.getAttribute(REDIRECT_URI);
        String clientId = (String) session.getAttribute(CLIENT_ID);
        String scopeList = (String) session.getAttribute(SCOPE);
        if (loginAttemptService.isBlocked(request.getRemoteAddr())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "This IP is blocked");
        }
        Application application = authFlow.getApplicationByClientIdAndRedirect(clientId, redirectUri);
        if (!result.hasErrors()) {
            try {
                User user = authFlow.checkLogin(login.getUserName(), login.getPassword(), clientId, request.getRemoteAddr(), scopeList.split(","));
                loginAttemptService.loginSucceeded(request.getRemoteAddr());
                if (authFlow.needsUserPermissionForApp(user, clientId)) {
                    // not yet implemented.
                } else {
                    redirectAttributes.addAttribute("code", authFlow.createLoginToken(login.getUserName()));
                    redirectAttributes.addAttribute(STATE, session.getAttribute(STATE));
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
            }
        }

        model.addAttribute("login", login);
        model.addAttribute("appName", application.getName());
        model.addAttribute("appCss", application.getCss());

        return "authorize";
    }

    @PostMapping("/cancel")
    public RedirectView cancelSubmit(@ModelAttribute LoginForm greeting, RedirectAttributes redirectAttributes, HttpSession session) {
        String redirectUri = (String) session.getAttribute(REDIRECT_URI);
        redirectAttributes.addAttribute("error.id", "user.cancelled");
        redirectAttributes.addAttribute("error.message", "The user has cancelled the login");
        redirectAttributes.addAttribute(STATE, session.getAttribute(STATE));
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
