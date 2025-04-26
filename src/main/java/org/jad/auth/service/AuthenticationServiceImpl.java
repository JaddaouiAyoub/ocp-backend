package org.jad.auth.service;

import lombok.RequiredArgsConstructor;

import org.jad.auth.User;
import org.jad.auth.auth.AuthRequest;
import org.jad.auth.auth.AuthResponse;
import org.jad.auth.auth.RefreshTokenRequest;
import org.jad.auth.auth.SignupRequest;
import org.jad.auth.enums.Role;
import org.jad.auth.exception.*;
import org.jad.auth.repository.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService{

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final EmailService emailService;

    @Override
    public User signup(SignupRequest signupRequest){
        User user= new User();
        user.setEmail(signupRequest.getEmail());
        user.setUsername(signupRequest.getUsername());
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        user.setRole(Role.USER);
        System.out.println("User to be created: " + user.getEmail());
        return userRepository.save(user);
    }


    @Override
    public AuthResponse signin(AuthRequest authRequest) {
        User user = userRepository.findByUsername(authRequest.getUsername());

        if (user == null) {
            throw new IllegalArgumentException("L'email ou le mot de passe est incorrect.");
        }

        // Authentification
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        } catch (Exception e) {
            throw new IllegalArgumentException("L'email ou le mot de passe est incorrect.");
        }

        // Génération du JWT et du refresh token
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        AuthResponse authResponse = new AuthResponse();
        authResponse.setEmail(user.getEmail());
        authResponse.setRole(user.getRole());
        authResponse.setToken(jwt);
        authResponse.setRefreshToken(refreshToken);
        return authResponse;
    }

    @Override
    public AuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        // Extraire l'email de l'utilisateur à partir du token de rafraîchissement
        String username = jwtService.extractUsername(refreshTokenRequest.getToken());
        User user = userRepository.findByUsername(username);

        if (user == null) {
            System.out.println("User not found with email: " + username); // Log pour l'utilisateur non trouvé
            throw new IllegalArgumentException("User not found!");
        }

        // Vérifier si le token de rafraîchissement est valide
        if (jwtService.isTokenValid(refreshTokenRequest.getToken(), user)) {
            var jwt = jwtService.generateToken(user);

            AuthResponse authResponse = new AuthResponse();
            authResponse.setRole(user.getRole());
            authResponse.setToken(jwt);
            authResponse.setRefreshToken(refreshTokenRequest.getToken());

            // Log pour indiquer que le token a été rafraîchi avec succès
            System.out.println("Access token refreshed for user: " + username);
            return authResponse;
        } else {
            // Log pour indiquer que le token de rafraîchissement est invalide ou expiré
            System.out.println("Invalid or expired refresh token for user: " + username);
        }

        return null;
    }

    @Override
    public boolean forgotPassword(String email) {
        User user = userRepository.findByEmail(email);
        if (user != null) {
            String newPassword = generateRandomPassword();
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            return true;
        }
        return false;
    }
//    @Override
//    public boolean changePassword(String email, String oldPassword, String newPassword) {
//        User user = userRepository.findByEmail(email);
//        if (user == null) {
//            throw new RessourceNotFoundException("Utilisateur non trouvé");
//        }
//
//        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
//            throw new UnauthorizedActionException("Ancien mot de passe incorrect");
//        }
//
//        user.setPassword(passwordEncoder.encode(newPassword));
//        userRepository.save(user);
//
//        // Envoi d'email
//        emailService.sendPasswordChangedNotification(user.getEmail());
//
//        return true;
//    }



    public String generateRandomPassword() {
        int length = 12; // Longueur du mot de passe
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;':\",.<>?";
        Random random = new Random();
        StringBuilder password = new StringBuilder(length);

        // S'assurer que le mot de passe contient au moins une lettre, un chiffre et un caractère spécial
        password.append(characters.charAt(random.nextInt(26))); // Lettre majuscule
        password.append(characters.charAt(random.nextInt(26) + 26)); // Lettre minuscule
        password.append(characters.charAt(random.nextInt(10) + 52)); // Chiffre
        password.append(characters.charAt(random.nextInt(32) + 62)); // Caractère spécial

        // Compléter le mot de passe avec des caractères aléatoires
        for (int i = 4; i < length; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }

        // Mélanger les caractères pour plus de sécurité
        return shuffleString(password.toString());
    }

    private String shuffleString(String input) {
        char[] passwordArray = input.toCharArray();
        Random random = new Random();
        for (int i = passwordArray.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            // Échange des caractères
            char temp = passwordArray[i];
            passwordArray[i] = passwordArray[j];
            passwordArray[j] = temp;
        }
        return new String(passwordArray);
    }


    @Override
    public ResponseEntity<Map<String, String>> changePassword(String email, String oldPassword, String newPassword) {
        // Trouver l'utilisateur par email
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new RessourceNotFoundException("Adresse e-mail non trouvée.");
        }

        // Vérifier si l'ancien mot de passe est correct
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new InvalidOldPasswordException("L'ancien mot de passe est incorrect.");
        }

        // Vérifier si les nouveaux mots de passe correspondent
//        if (!newPassword.equals(confirmPassword)) {
//            throw new InvalidNewPasswordException("Les nouveaux mots de passe ne correspondent pas.");
//        }

        // Valider la force du nouveau mot de passe
        String validationMessage = validatePassword(newPassword);
        if (!"Mot de passe valide.".equals(validationMessage)) {
            throw new InvalidPasswordStrengthException(validationMessage);
        }

        // Mettre à jour le mot de passe
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Envoyer une notification par email
        emailService.sendPasswordChangedNotification(user.getEmail());

        Map<String, String> response = new HashMap<>();
        response.put("message", "Le mot de passe a été changé avec succès.");
        return ResponseEntity.ok(response);
    }


    private String validatePassword(String password) {
        if (password.length() < 8) {
            return "Le mot de passe doit contenir au moins 8 caractères.";
        }
        if (!password.matches(".*[0-9].*")) {
            return "Le mot de passe doit contenir au moins un chiffre.";
        }
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*")) {
            return "Le mot de passe doit contenir au moins un caractère spécial.";
        }
        if (!password.matches(".*[A-Z].*")) {
            return "Le mot de passe doit contenir au moins une lettre majuscule.";
        }
        if (!password.matches(".*[a-z].*")) {
            return "Le mot de passe doit contenir au moins une lettre minuscule.";
        }
        return "Mot de passe valide.";
    }

}
