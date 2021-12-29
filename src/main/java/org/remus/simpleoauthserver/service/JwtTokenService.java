package org.remus.simpleoauthserver.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Component
public class JwtTokenService {

    @Value("${jwt.expiration}")
    private Long expiration;

    @Value("${jwt.short.expiration}")
    private Long shortExpiration;

    @Value("${jwt.long.expiration}")
    private Long longExpiration;

    private KeyService keyService;

    public JwtTokenService(KeyService keyService) {
        this.keyService = keyService;
    }

    public String createAccessToken(String subject, ApplicationType type, String[] scopeList) {
        final Date createdDate = new Date();
        final Date expirationDate = calculateExpirationDate(createdDate);

        return Jwts.builder()
                .setClaims(new HashMap<>())
                .setSubject(subject)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.RS256, keyService.getPrivateKey())
                .claim("scope", String.join(",",scopeList))
                .claim("type", type)
                .compact();
    }

    public String createAuthorizationToken(String username) {
        final Date createdDate = new Date();
        final Date expirationDate = calculateShortExpirationDate(createdDate);

        return Jwts.builder()
                .setClaims(new HashMap<>())
                .setSubject(username)
                .setIssuedAt(createdDate)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.RS256, keyService.getPrivateKey())
                .compact();
    }

    private Date calculateExpirationDate(Date createdDate) {
        return new Date(createdDate.getTime() + expiration * 1000);
    }
    private Date calculateShortExpirationDate(Date createdDate) {
        return new Date(createdDate.getTime() + shortExpiration * 1000);
    }

    private Date calculateLongExpirationDate(Date createdDate) {
        return new Date(createdDate.getTime() + longExpiration * 1000);
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(keyService.getPublicKey())
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims != null;
    }
}
