package com.codedifferently.firebaseauthexample.security.filters;

import com.codedifferently.firebaseauthexample.security.enums.CredentialType;
import com.codedifferently.firebaseauthexample.security.models.Credentials;
import com.codedifferently.firebaseauthexample.security.models.FireBaseUser;
import com.codedifferently.firebaseauthexample.security.models.SecurityProperties;
import com.codedifferently.firebaseauthexample.security.utils.CookieUtils;
import com.codedifferently.firebaseauthexample.security.utils.services.SecurityService;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {
    private Logger logger = LoggerFactory.getLogger(SecurityFilter.class);
    private SecurityService securityService;
    private SecurityProperties restSecProps;
    private CookieUtils cookieUtils;
    private SecurityProperties securityProps;

    @Autowired
    public SecurityFilter(SecurityService securityService, SecurityProperties restSecProps, CookieUtils cookieUtils, SecurityProperties securityProps) {
        this.securityService = securityService;
        this.restSecProps = restSecProps;
        this.cookieUtils = cookieUtils;
        this.securityProps = securityProps;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        verifyToken(request);
        filterChain.doFilter(request, response);
    }

    private void verifyToken(HttpServletRequest request) {
        String session = null;
        FirebaseToken decodedToken = null;
        CredentialType type = null;
        boolean strictServerSessionEnabled = securityProps.getFirebaseProps().isEnableStrictServerSession();
        Cookie sessionCookie = cookieUtils.getCookie("session");
        String token = securityService.getBearerToken(request);
        try {
            if (sessionCookie != null) {
                session = sessionCookie.getValue();
                decodedToken = FirebaseAuth.getInstance().verifySessionCookie(session,
                        securityProps.getFirebaseProps().isEnableCheckSessionRevoked());
                type = CredentialType.SESSION;
            } else if (!strictServerSessionEnabled) {
                if (token != null && !token.equalsIgnoreCase("undefined")) {
                    decodedToken = FirebaseAuth.getInstance().verifyIdToken(token);
                    type = CredentialType.ID_TOKEN;
                }
            }
        } catch (FirebaseAuthException e) {
            e.printStackTrace();
            logger.error("Firebase Exception:: ", e.getLocalizedMessage());
        }
        FireBaseUser user = firebaseTokenToUserDto(decodedToken);
        if (user != null) {
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user,
                    new Credentials(type, decodedToken, token, session), null);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }

    private FireBaseUser firebaseTokenToUserDto(FirebaseToken decodedToken) {
        FireBaseUser user = null;
        if (decodedToken != null) {
            user = new FireBaseUser();
            user.setUid(decodedToken.getUid());
            user.setName(decodedToken.getName());
            user.setEmail(decodedToken.getEmail());
            user.setPicture(decodedToken.getPicture());
            user.setIssuer(decodedToken.getIssuer());
            user.setEmailVerified(decodedToken.isEmailVerified());
        }
        return user;
    }


}
