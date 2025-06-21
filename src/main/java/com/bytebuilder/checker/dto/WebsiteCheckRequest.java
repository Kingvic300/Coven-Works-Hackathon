package com.bytebuilder.checker.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;


@Data
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request to check website security and safety")
public class WebsiteCheckRequest {

    @NotBlank(message = "URL cannot be blank")
    @Size(max = 2048, message = "URL length cannot exceed 2048 characters")
    @Pattern(
            regexp = "^(https?://)?(www\\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}(:[0-9]{1,5})?(/.*)?$",
            message = "Invalid URL format"
    )
    @Schema(description = "Website URL to check", example = "https://example.com")
    private String url;

    @Schema(description = "Optional: Include detailed analysis", example = "true")
    private boolean includeDetails = true;

    @Schema(description = "Optional: Timeout for analysis in seconds", example = "30")
    private Integer timeoutSeconds;
}