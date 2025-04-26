package org.jad.auth.service;


import org.jad.auth.User;
import org.jad.auth.auth.AuthRequest;
import org.jad.auth.auth.AuthResponse;
import org.jad.auth.auth.RefreshTokenRequest;
import org.jad.auth.auth.SignupRequest;
import org.springframework.http.ResponseEntity;

import java.util.Map;

public interface AuthenticationService {
    User signup(SignupRequest authRequest);

    AuthResponse signin(AuthRequest authRequest);

    AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest);

    boolean forgotPassword(String email);

//    boolean changePassword(String email, String oldPassword, String newPassword);


    ResponseEntity<Map<String, String>> changePassword(String email, String oldPassword, String newPassword);
}
