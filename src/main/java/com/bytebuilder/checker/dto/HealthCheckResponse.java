package com.bytebuilder.checker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response for service health check")
public class HealthCheckResponse {
    @Schema(description = "Status message", example = "Website Check Service is running.")
    private String message;

    @Schema(description = "True if the service is healthy, false otherwise")
    private boolean healthy;
}