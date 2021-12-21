package org.remus.simpleoauthserver.controller;


import org.remus.simpleoauthserver.request.CreateSuperAdminRequest;
import org.remus.simpleoauthserver.service.SetupService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/auth/setup")
public class SetupController {
    private SetupService setupService;

    public SetupController(SetupService setupService) {
        this.setupService = setupService;
    }

    @PostMapping(path = "createInitialSuperAdmin")
    public void createSuperAdmin(@RequestBody CreateSuperAdminRequest request) {
        if (setupService.canCreateInitialSuperAdmin(request.getInitialAuthToken())) {
            setupService.createInitialSuperAdmin(request.getSuperAdminEmail(),
                    request.getSuperAdminPassword(),request.getSuperAdminName(),request.getOrganization());
        } else {

        }
    }
}
