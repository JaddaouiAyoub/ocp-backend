package org.jad.auth;

import lombok.RequiredArgsConstructor;

import org.jad.auth.auth.*;
import org.jad.auth.exception.RessourceNotFoundException;
import org.jad.auth.exception.UnauthorizedActionException;
import org.jad.auth.service.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);


    @PostMapping("/signup")
    public ResponseEntity<User> signup(@RequestBody SignupRequest signupRequest){
        System.out.println(signupRequest);
        return ResponseEntity.ok(authenticationService.signup(signupRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {
        try {
            AuthResponse authResponse = authenticationService.signin(authRequest);
            return ResponseEntity.ok(authResponse);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage()); // Erreur 401
        }
    }
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            AuthResponse authResponse = authenticationService.refreshToken(refreshTokenRequest);
            return ResponseEntity.ok(authResponse);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null); // 401 Unauthorized
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null); // 500 Internal Server Error
        }
    }
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@RequestBody Map<String, String> request) {

        Map<String, String> response = new HashMap<>();
        try {
            String email = request.get("email");

        boolean isEmailValid = authenticationService.forgotPassword(email);


        if (isEmailValid) {
            response.put("message", "Un nouveau mot de passe a été envoyé à votre adresse e-mail.");
            return ResponseEntity.ok(response);
        } else {
            response.put("error", "Adresse e-mail non trouvée.");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
        }catch (Exception e){
            logger.error("Erreur lors de l'appel forgot-password", e);
            response.put("message", "Erreur lors de l'appel forgot-password.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@RequestBody ChangePasswordRequest request) {
        Map<String, String> response = new HashMap<>();
        try {
            return authenticationService.changePassword(
                    request.getEmail(),
                    request.getOldPassword(),
                    request.getNewPassword()
            );

//            if (success) {
//                response.put("message", "Mot de passe changé avec succès. Un email de confirmation a été envoyé.");
//                return ResponseEntity.ok(response);
//            } else {
//                response.put("message", "Erreur lors du changement de mot de passe.");
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
//            }
        } catch (Exception e) {
            response.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }


//    @PostMapping("/change-password")
//    public ResponseEntity<Map<String, String>> changePassword(@Valid @RequestBody ChangePasswordRequest changePasswordRequest) {
//        try {
//            // Appeler votre service pour gérer le changement de mot de passe
//            return authenticationService.changePassword(
//                    changePasswordRequest.getEmail(),
//                    changePasswordRequest.getOldPassword(),
//                    changePasswordRequest.getNewPassword(),
//                    changePasswordRequest.getConfirmPassword()
//            );
//        } catch (RessourceNotFoundException ex) {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", ex.getMessage()));
//        } catch (UnauthorizedActionException ex) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", ex.getMessage()));
//        } catch (InsufficientLeaveBalanceException ex) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", ex.getMessage()));
//        } catch (InvalidOldPasswordException ex) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", ex.getMessage()));
//        } catch (InvalidNewPasswordException ex) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", ex.getMessage()));
//        } catch (InvalidPasswordStrengthException ex) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", ex.getMessage()));
//        } catch (Exception ex) {
//            // Pour toutes les autres exceptions non gérées
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                    .body(Map.of("message", "Une erreur inattendue est survenue."));
//        }
//    }





}