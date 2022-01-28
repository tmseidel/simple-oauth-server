package org.remus.simpleoauthserver.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.RandomStringUtils;
import org.remus.simpleoauthserver.config.KeyServiceConfig;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Service
public class KeyService {

    private KeyServiceConfig config;

    private static class JWTKeys {
        private String authorizationToken;
        private String refreshTokenKey;
        private String formTokenKey;

        public String getAuthorizationToken() {
            return authorizationToken;
        }

        public void setAuthorizationToken(String authorizationToken) {
            this.authorizationToken = authorizationToken;
        }

        public String getRefreshTokenKey() {
            return refreshTokenKey;
        }

        public void setRefreshTokenKey(String refreshTokenKey) {
            this.refreshTokenKey = refreshTokenKey;
        }

        public String getFormTokenKey() {
            return formTokenKey;
        }

        public void setFormTokenKey(String formTokenKey) {
            this.formTokenKey = formTokenKey;
        }
    }

    private PrivateKey privateKey;

    private PublicKey publicKey;

    private JWTKeys jwtKeys;

    public KeyService(KeyServiceConfig config) {
        this.config = config;
    }

    public String getAuthorizationTokenKey() {
        if (jwtKeys == null) {
            loadJWTKeys();
        }
        return jwtKeys.getAuthorizationToken();
    }

    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(Paths.get(config.getBasePath()));
        } catch (IOException e) {
            throw new IllegalStateException("Could not create a needed directory");
        }
    }

    public String getRefrehTokenKey() {
        if (jwtKeys == null) {
            loadJWTKeys();
        }
        return jwtKeys.getRefreshTokenKey();
    }

    public String getFormTokenKey() {
        if (jwtKeys == null) {
            loadJWTKeys();
        }
        return jwtKeys.getFormTokenKey();
    }

    private synchronized void loadJWTKeys() {
        File file = Paths.get(config.getJwtKeysLocation()).toFile();
        try {
            this.jwtKeys = new ObjectMapper().readValue(file,JWTKeys.class);
        } catch (IOException e) {
            throw new IllegalStateException("Error while loading jwt-signature-keys",e);
        }
    }

    public synchronized void createKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator kpg = null;
        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        try (FileOutputStream fos = new FileOutputStream(config.getPrivateKeyLocation())) {
            fos.write(privateKey.getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream(config.getPublicKeyLocation())) {
            fos.write(publicKey.getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream(config.getJwtKeysLocation())) {
            JWTKeys keys = new JWTKeys();
            keys.setAuthorizationToken(RandomStringUtils.random(32, true, true));
            keys.setRefreshTokenKey(RandomStringUtils.random(32, true, true));
            keys.setFormTokenKey(RandomStringUtils.random(32, true, true));
            new ObjectMapper().writeValue(fos,keys);
            loadJWTKeys();
        }

    }

    public PrivateKey getPrivateKey() {
        if (privateKey == null) {
            try {
                Path path = Paths.get(config.getPrivateKeyLocation());
                byte[] bytes = Files.readAllBytes(path);
                PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                privateKey = kf.generatePrivate(ks);
            } catch (IOException | GeneralSecurityException e) {
                throw new IllegalStateException("The private key is not present or corrupt", e);
            }

        }
        return privateKey;
    }

    public PublicKey getPublicKey() {
        if (publicKey == null) {
            try {
                Path path = Paths.get(config.getPublicKeyLocation());
                byte[] bytes = Files.readAllBytes(path);
                X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                publicKey = kf.generatePublic(ks);
            } catch (IOException | GeneralSecurityException e) {
                throw new IllegalStateException("The public key is not present or corrupt", e);
            }

        }
        return publicKey;
    }
}
