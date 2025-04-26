package org.jad.auth.exception;

public class InvalidPasswordStrengthException extends RuntimeException {
    public InvalidPasswordStrengthException(String message) {
        super(message);
    }
}
