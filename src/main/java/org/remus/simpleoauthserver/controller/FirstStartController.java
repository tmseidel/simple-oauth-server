package org.remus.simpleoauthserver.controller;


import org.remus.simpleoauthserver.request.CreateSuperAdminRequest;
import org.remus.simpleoauthserver.service.KeyService;
import org.remus.simpleoauthserver.service.SetupService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@RestController
@RequestMapping(path = "/auth/firstStart")
public class FirstStartController {
    private SetupService setupService;

    private KeyService keyService;

    public FirstStartController(SetupService setupService, KeyService keyService) {
        this.setupService = setupService;
        this.keyService = keyService;
    }


    @PostMapping(path = "run")
    public void run(@RequestBody CreateSuperAdminRequest request) throws NoSuchAlgorithmException, IOException {
        if (setupService.canCreateInitialSuperAdmin(request.getInitialAuthToken())) {
            keyService.createKeyPair();
            setupService.createInitialSuperAdmin(request.getSuperAdminEmail(),
                    request.getSuperAdminPassword(), request.getSuperAdminName(), request.getOrganization());
        } else {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "This operation is not available.");
        }
    }

    @GetMapping(produces = MediaType.TEXT_PLAIN_VALUE, path = "pub")
    public ResponseEntity<byte[]> streamPublicKey() {
        try {
            byte[] bytes = keyService.getPublicKey().getEncoded();
            return ResponseEntity.ok().contentLength(bytes.length).contentType(MediaType.APPLICATION_OCTET_STREAM).header("Content-Disposition", "attachment;filename=\"publicKey.pub\"").body(bytes);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }
}
