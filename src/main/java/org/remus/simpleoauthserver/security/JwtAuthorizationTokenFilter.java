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
package org.remus.simpleoauthserver.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.remus.simpleoauthserver.config.Configuration;
import org.remus.simpleoauthserver.entity.ApplicationType;
import org.remus.simpleoauthserver.service.JwtTokenService;
import org.remus.simpleoauthserver.service.TokenBinService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.inject.Named;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.remus.simpleoauthserver.service.JwtTokenService.TokenType.ACCESS;

@Component
public class JwtAuthorizationTokenFilter extends OncePerRequestFilter {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final JwtTokenService jwtTokenUtil;

    @Value("${jwt.header}")
    private String tokenHeader;

    private final UserDetailsService appBasedDetailService;

    private final UserDetailsService userBasedDetailService;

    private final TokenBinService tokenBinService;

    public JwtAuthorizationTokenFilter(JwtTokenService jwtTokenUtil,
                                       @Named(Configuration.BEAN_NAME_USERBASED_DETAILSERVICE) UserDetailsService userDetailsService,
                                       @Named(Configuration.BEAN_NAME_APPBASED_DETAILSERVICE) UserDetailsService appbasedDetailService,
                                       TokenBinService tokenBinService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.userBasedDetailService = userDetailsService;
        this.appBasedDetailService = appbasedDetailService;
        this.tokenBinService = tokenBinService;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        log.debug("processing authentication for '{}'", request.getRequestURL());

        final String requestHeader = request.getHeader(this.tokenHeader);

        String username = null;
        ApplicationType applicationType = ApplicationType.REGULAR;
        String authToken = null;
        if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
            authToken = requestHeader.substring(7);
            try {
                String[] claims = jwtTokenUtil.getClaimFromToken(authToken,e -> {
                    String[] returnValue = new String[2];
                    returnValue[0] = e.getSubject();
                    returnValue[1] = e.get("type",String.class);
                    return returnValue;
                }, ACCESS);
                username = claims[0];
                applicationType = ApplicationType.valueOf(claims[1]);

            } catch (IllegalArgumentException e) {
                log.error("an error occurred during getting username from token", e);
            } catch (ExpiredJwtException e) {
                log.warn("the token is expired and not valid anymore", e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed");
                return;
            } catch (JwtException e) {
                log.warn("there was an error with the token, aborting",e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed");
                return;
            }
        } else {
            log.debug("couldn't find bearer string, will ignore the header");
        }

        log.debug("checking authentication for user '{}'", username);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            log.debug("security context was null, so authorizing user");
            UserDetails userDetails;
            try {
                switch (applicationType) {
                    case M2M:
                        userDetails = appBasedDetailService.loadUserByUsername(username);
                        break;
                    case REGULAR:
                        userDetails = userBasedDetailService.loadUserByUsername(username);
                        break;
                    default:
                        throw new IllegalStateException("Unexpected value: " + applicationType);
                }
                
            } catch (UsernameNotFoundException e) {
                return;
            }
            checkUserDetailsAndSetAuth(request, authToken, userDetails);
        }

        chain.doFilter(request, response);
    }

    private void checkUserDetailsAndSetAuth(HttpServletRequest request, String authToken, UserDetails userDetails) {
        if (userDetails != null && !tokenBinService.isTokenInvalidated(authToken)) {
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            log.info("authorized user '{}', setting security context", userDetails.getUsername());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }
}
