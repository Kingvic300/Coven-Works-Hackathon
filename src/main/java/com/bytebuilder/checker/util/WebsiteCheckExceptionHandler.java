package com.bytebuilder.checker.util;

import com.bytebuilder.checker.dto.ErrorResponse; // Ensure this import is correct
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.net.URISyntaxException;
import java.time.Instant;
import java.util.stream.Collectors;

@ControllerAdvice
@Slf4j
public class WebsiteCheckExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.error("Invalid argument provided: {}", ex.getMessage());
        // FIX: Provide all three arguments required by @AllArgsConstructor
        // Assuming your ErrorResponse takes (String message, String details, long timestamp)
        ErrorResponse errorResponse = new ErrorResponse(
                "Bad Request",
                ex.getMessage(),
                Instant.now().toEpochMilli() // Provide the timestamp
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(URISyntaxException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ErrorResponse> handleURISyntaxException(URISyntaxException ex) {
        log.error("Invalid URI syntax: {}", ex.getMessage());
        // FIX: Provide all three arguments required by @AllArgsConstructor
        ErrorResponse errorResponse = new ErrorResponse(
                "Invalid URL Format",
                "The provided URL has an invalid syntax. Please check the format.",
                Instant.now().toEpochMilli() // Provide the timestamp
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));
        log.error("Validation failed: {}", errorMessage);
        // FIX: Provide all three arguments required by @AllArgsConstructor
        ErrorResponse errorResponse = new ErrorResponse(
                "Validation Error",
                "One or more input fields are invalid: " + errorMessage,
                Instant.now().toEpochMilli() // Provide the timestamp
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<ErrorResponse> handleTypeMismatchException(MethodArgumentTypeMismatchException ex) {
        String errorDetails = String.format("Parameter '%s' should be of type '%s' but was '%s'.",
                ex.getName(), ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "unknown",
                ex.getValue());
        log.error("Method argument type mismatch: {}", errorDetails);
        // FIX: Provide all three arguments required by @AllArgsConstructor
        ErrorResponse errorResponse = new ErrorResponse(
                "Invalid Input Type",
                errorDetails,
                Instant.now().toEpochMilli() // Provide the timestamp
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }


    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ErrorResponse> handleRuntimeException(RuntimeException ex) {
        log.error("An unexpected internal server error occurred: {}", ex.getMessage(), ex);
        // FIX: Provide all three arguments required by @AllArgsConstructor
        ErrorResponse errorResponse = new ErrorResponse(
                "Internal Server Error",
                "An unexpected error occurred during website analysis. Please try again later.",
                Instant.now().toEpochMilli() // Provide the timestamp
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ResponseEntity<ErrorResponse> handleAllUncaughtException(Exception ex) {
        log.error("An uncaught exception occurred: {}", ex.getMessage(), ex);
        // FIX: Provide all three arguments required by @AllArgsConstructor
        ErrorResponse errorResponse = new ErrorResponse(
                "Unexpected Error",
                "An unexpected error occurred. Please contact support.",
                Instant.now().toEpochMilli() // Provide the timestamp
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}