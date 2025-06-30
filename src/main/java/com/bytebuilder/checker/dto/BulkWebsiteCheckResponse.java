package com.bytebuilder.checker.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Bulk website check response")
public class BulkWebsiteCheckResponse {

    @Schema(description = "Individual results for each URL")
    private java.util.List<WebsiteCheckResponse> results;

    @Schema(description = "Summary statistics")
    private BulkAnalysisSummary summary;

    @Schema(description = "When the bulk analysis was completed")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    private Instant completedAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @Schema(description = "Summary statistics for a bulk analysis")
    public static class BulkAnalysisSummary {
        private int totalUrls;
        private int safeUrls;
        private int unsafeUrls;
        private int failedAnalyses;
        private long totalAnalysisTimeMs;
    }
}