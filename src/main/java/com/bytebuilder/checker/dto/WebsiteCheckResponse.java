package com.bytebuilder.checker.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Website security and safety analysis result")
public class WebsiteCheckResponse {

    @Schema(description = "Analyzed URL", example = "https://example.com")
    private String url;

    @Schema(description = "Website description extracted from content")
    private String description;

    @Schema(description = "Whether the website uses HTTPS securely")
    private boolean isSecure;

    @Schema(description = "Whether the website is safe from malware/scams based on external scanners")
    private boolean isSafeFromScams;

    @Schema(description = "Whether the website content appears safe (no suspicious keywords)")
    private boolean isTextSafe;

    @Schema(description = "Whether the URL itself appears suspicious")
    private boolean isUrlSuspicious;

    @Schema(description = "Overall safety assessment (true if all checks pass)")
    private boolean overallSafe;

    @Schema(description = "Human-readable safety message")
    private String message;

    @Schema(description = "When the analysis was performed")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
    private Instant analyzedAt;

    @Schema(description = "Additional technical information about the analysis (e.g., analysis time, specific detected keywords)")
    private Map<String, Object> additionalInfo;

    // Computed property for backward compatibility, same as isSafeFromScams
    @Schema(description = "Legacy field: true if website is safe from scams/malware, false otherwise.")
    public boolean isSafe() {
        return isSafeFromScams;
    }
}