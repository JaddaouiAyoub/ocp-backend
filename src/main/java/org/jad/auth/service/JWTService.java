package org.jad.auth.service;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

public interface JWTService {

    String generateRefreshToken(Map<String, Object> extractClaims, UserDetails userDetails);

    String extractUsername(String token);
    String generateToken(UserDetails userDetails);

    boolean isTokenValid(String token, UserDetails userDetails);



}