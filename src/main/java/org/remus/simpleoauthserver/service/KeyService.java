package org.remus.simpleoauthserver.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Service
public class KeyService {

    @Value("${jwt.privatekey.location}")
    private String privateKeyLocation;

    @Value("${jwt.publickey.location}")
    private String publicKeyLocation;

    private PrivateKey privateKey;

    private PublicKey publicKey;

    public void createKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator kpg = null;
        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        try (FileOutputStream fos = new FileOutputStream(privateKeyLocation)) {
            fos.write(privateKey.getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream(publicKeyLocation)) {
            fos.write(publicKey.getEncoded());
        }
    }

    public PrivateKey getPrivateKey() {
        if (privateKey == null) {
            try {
                Path path = Paths.get(privateKeyLocation);
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
                Path path = Paths.get(publicKeyLocation);
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
