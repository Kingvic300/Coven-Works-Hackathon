package com.bytebuilder.checker.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request for email spam detection")
public class EmailSpamCheckRequest {

    @NotBlank(message = "Email subject is required")
    @Schema(description = "Email subject line", example = "Congratulations! You've won a prize!")
    private String subject;

    @NotBlank(message = "Email content is required")
    @Schema(description = "Email body content", example = "Click here to claim your prize...")
    private String content;

    @NotBlank(message = "Sender email is required")
    @Schema(description = "Sender email address", example = "sender@example.com")
    private String sender;

    @Schema(description = "Recipient email address (optional)", example = "recipient@example.com")
    private String recipient;
} 