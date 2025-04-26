package org.jad.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTServiceImpl implements JWTService{

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.access.token.expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.token.expiration}")
    private long refreshTokenExpiration;

    private Key getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        String token = Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();

        // Log pour indiquer la génération d'un token d'accès
        System.out.println("Access token generated for user: " + userDetails.getUsername());
        return token;
    }

    @Override
    public String generateRefreshToken(Map<String, Object> extractClaims, UserDetails userDetails) {
        String refreshToken = Jwts.builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();

        // Log pour indiquer la génération d'un token de rafraîchissement
//        System.out.println("Refresh token generated for user: " + userDetails.getUsername());
        return refreshToken;
    }


    @Override
    public String extractUsername(String token) {
        String username = extractClaim(token, Claims::getSubject);

        // Log pour indiquer l'extraction de l'utilisateur à partir du token
//        System.out.println("Username extracted from token: " + username);

        return username;
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        boolean isValid = (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

        // Log pour indiquer la validation du token
        if (isValid) {
//            System.out.println("Token is valid for user: " + username);
        } else {
            System.out.println("Token is invalid or expired for user: " + username);
        }

        return isValid;
    }

    private boolean isTokenExpired(String token) {
        boolean isExpired = extractClaim(token, Claims::getExpiration).before(new Date());

        // Log pour indiquer l'expiration du token
        if (isExpired) {
            System.out.println("Token has expired.");
        }

        return isExpired;
    }

}