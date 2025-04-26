package org.jad.auth.exception.handler;


import org.jad.auth.exception.*;
import org.jad.auth.response.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class AppExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(AppExceptionHandler.class);

    private ResponseEntity<Object> buildErrorResponse(String message, HttpStatus status) {
        ApiResponse<Object> response = ApiResponse.builder()
                .error(message)
                .timestamp(LocalDateTime.now())
                .code(status.value())
                .build();
        return new ResponseEntity<>(response, status);
    }

    @ExceptionHandler(value = {RessourceNotFoundException.class})
    public ResponseEntity<Object> handleResourceNotFoundException(RessourceNotFoundException ex) {
        logger.error("Resource not found: {}", ex.getMessage());
        return buildErrorResponse(ex.getMessage(), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(value = {RessourceAlreadyExistsException.class})
    public ResponseEntity<Object> handleResourceAlreadyExistsException(RessourceAlreadyExistsException ex) {
        logger.error("Resource already exists: {}", ex.getMessage());
        return buildErrorResponse(ex.getMessage(), HttpStatus.CONFLICT);
    }

    @ExceptionHandler(value = MethodArgumentNotValidException.class)
    public ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));

        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .data(errors)
                .error("Validation failed")
                .timestamp(LocalDateTime.now())
                .code(HttpStatus.UNPROCESSABLE_ENTITY.value())
                .build();

        logger.error("Validation failed: {}", errors);
        return new ResponseEntity<>(response, new HttpHeaders(), HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(value = Exception.class)
    public ResponseEntity<Object> handleAllExceptions(Exception ex) {
        logger.error("An unexpected error occurred: {}", ex.getMessage(), ex);
        return buildErrorResponse("An unexpected error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(value = UnauthorizedActionException.class)
    public ResponseEntity<Object> handleUnauthorizedActionException(UnauthorizedActionException ex) {
        logger.error("Unauthorized action: {}", ex.getMessage());
        return buildErrorResponse(ex.getMessage(), HttpStatus.UNAUTHORIZED);
    }
    @ExceptionHandler(value = InsufficientLeaveBalanceException.class)
    public ResponseEntity<Object> handleInsufficientLeaveBalanceException(InsufficientLeaveBalanceException ex) {
        logger.error("Insufficient leave balance: {}", ex.getMessage());
        return buildErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }
    @ExceptionHandler(value = {InvalidOldPasswordException.class})
    public ResponseEntity<Object> handleInvalidOldPasswordException(InvalidOldPasswordException ex) {
        logger.error("Invalid old password: {}", ex.getMessage());
        return buildErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(value = {InvalidNewPasswordException.class})
    public ResponseEntity<Object> InvalidNewPasswordException(InvalidNewPasswordException ex) {
        logger.error("Password mismatch: {}", ex.getMessage());
        return buildErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(value = {InvalidPasswordStrengthException.class})
    public ResponseEntity<Object> handleInvalidPasswordStrengthException(InvalidPasswordStrengthException ex) {
        logger.error("Invalid password strength: {}", ex.getMessage());
        return buildErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST);
    }


}
