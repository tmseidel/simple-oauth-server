package org.remus.simpleoauthserver.controller;

import org.remus.simpleoauthserver.entity.Application;
import org.remus.simpleoauthserver.flows.AuthorizationFlow;
import org.remus.simpleoauthserver.request.LoginForm;
import org.remus.simpleoauthserver.service.InvalidIpException;
import org.remus.simpleoauthserver.service.LoginAttemptService;
import org.remus.simpleoauthserver.service.LoginService;
import org.remus.simpleoauthserver.service.ScopeNotFoundException;
import org.remus.simpleoauthserver.service.UserLockedException;
import org.remus.simpleoauthserver.service.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Controller
@RequestMapping(path = "/auth/oauth2")
public class LoginController {


    public static final String STATE = "state";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String OAUTH_REDIRECT_URI = "oauth_redirect_uri";

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final LoginService loginService;

    private final LoginAttemptService loginAttemptService;

    private final UserValidator userValidator;

    private final AuthorizationFlow authFlow;


    public LoginController(UserValidator userValidator, LoginService loginService, LoginAttemptService loginAttemptService, AuthorizationFlow authFlow) {
        this.userValidator = userValidator;
        this.loginService = loginService;
        this.loginAttemptService = loginAttemptService;
        this.authFlow = authFlow;
    }

    @InitBinder
    protected void initBinder(WebDataBinder binder) {
        binder.addValidators(userValidator);
    }

    @GetMapping("/authorize")
    public String authorize(@RequestParam(name="client_id") String clientId,
                            @RequestParam(name="scope") String scope,
                            @RequestParam(name="response_type") String responseType,
                            @RequestParam(name= STATE, required=false) String state,
                            @RequestParam(name= REDIRECT_URI) String redirect,
                            @RequestParam(name="response_mode", required=false) String query,
                            Model model, HttpSession session) {
        authFlow.validateAuthorizationRequest(responseType,clientId,redirect,scope,state,query);
        Application application = authFlow.findApplication(clientId, redirect);
        model.addAttribute("login", new LoginForm());
        model.addAttribute("appName", application.getName());
        model.addAttribute("appCss", application.getCssUrl());
        session.setAttribute(STATE,state);
        session.setAttribute("client_id",clientId);
        session.setAttribute("scope",scope);
        session.setAttribute(OAUTH_REDIRECT_URI,redirect);

        logger.debug("Add state {}, client_id {}, scop {}, redirect_uri {} to session", state, clientId, scope, redirect);

        return "authorize";
    }

    @PostMapping("/authorize")
    public String authorizeSubmit(@ModelAttribute("login") @Validated LoginForm login, BindingResult result,
                                  Model model, RedirectAttributes redirectAttributes, HttpSession session, HttpServletRequest request) {

        String redirectUri = (String) session.getAttribute(OAUTH_REDIRECT_URI);
        String clientId = (String) session.getAttribute("client_id");
        String scopeList =  (String) session.getAttribute("scope");
        if (loginAttemptService.isBlocked(request.getRemoteAddr())) {
            throw new RuntimeException("This IP is blocked");
        }
        Application application = authFlow.findApplication(clientId, redirectUri);
        if (!result.hasErrors()) {

            try {
                loginService.checkUser(login.getUserName(),login.getPassword(),clientId, request.getRemoteAddr());
                loginService.checkScope(login.getUserName(), scopeList.split(","));
                redirectAttributes.addAttribute("code",loginService.createLoginToken(login.getUserName()));
                redirectAttributes.addAttribute(STATE,session.getAttribute(STATE));

                loginAttemptService.loginSucceeded(request.getRemoteAddr());
                return "redirect:" + redirectUri;
            } catch (UserNotFoundException e) {
                result.rejectValue("userName","user.not.found");
                loginAttemptService.loginFailed(request.getRemoteAddr());
            } catch (InvalidIpException e) {
                result.rejectValue("userName","user.ip.not.allowed");
            } catch (UserLockedException e) {
                result.rejectValue("userName","user.locked");
            } catch (ScopeNotFoundException e) {
                result.rejectValue("userName","scope.not.found");
            }
        }

        model.addAttribute("login", login);
        model.addAttribute("appName", application.getName());
        model.addAttribute("appCss", application.getCssUrl());

        return "authorize";
    }

    @PostMapping("/cancel")
    public RedirectView cancelSubmit(@ModelAttribute LoginForm greeting, RedirectAttributes redirectAttributes, HttpSession session) {
        String redirectUri = (String) session.getAttribute(OAUTH_REDIRECT_URI);
        redirectAttributes.addAttribute("error.id","user.cancelled");
        redirectAttributes.addAttribute("error.message","The user has cancelled the login");
        redirectAttributes.addAttribute(STATE,session.getAttribute(STATE));
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl(redirectUri);
        return redirectView;

    }
}
