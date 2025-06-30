package com.bytebuilder.checker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;



@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Bulk website check request")
public class BulkWebsiteCheckRequest {

    @Schema(description = "List of URLs to check", example = "[\"https://example.com\", \"https://test.com\"]")
    @Size(min = 1, max = 10, message = "Must provide between 1 and 10 URLs")
    private java.util.List<@NotBlank String> urls; // Annotation for each element in the list

    @Schema(description = "Whether to include detailed analysis for each URL")
    private boolean includeDetails = true;

    @Schema(description = "Maximum time to spend on each URL analysis (seconds)")
    private Integer timeoutPerUrl = 30;
}