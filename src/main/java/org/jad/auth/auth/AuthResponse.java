package org.jad.auth.auth;

import lombok.Data;
import org.jad.auth.enums.Role;

@Data
public class AuthResponse {

    private String token;
    private String refreshToken;
    private String email;
    private Role role;
}
