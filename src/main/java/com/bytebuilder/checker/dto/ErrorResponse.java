package com.bytebuilder.checker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Standardized error response format")
public class ErrorResponse {
    @Schema(description = "Unique error code", example = "INVALID_URL")
    private String code;

    @Schema(description = "Human-readable error message", example = "The provided URL format is invalid.")
    private String message;

    @Schema(description = "Timestamp of when the error occurred (milliseconds since epoch)")
    private long timestamp = System.currentTimeMillis(); // Default to current time on creation
}