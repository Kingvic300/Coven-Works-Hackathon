package com.bytebuilder.checker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Website safety score with detailed breakdown")
public class WebsiteSafetyScore {

    @Schema(description = "Overall safety score (0-100)", example = "85")
    private int overallScore;

    @Schema(description = "HTTPS security score (0-100)")
    private int httpsScore;

    @Schema(description = "Malware/scam detection score (0-100)")
    private int malwareScore;

    @Schema(description = "Content safety score (0-100)")
    private int contentScore;

    @Schema(description = "URL reputation score (0-100)")
    private int urlReputationScore;

    @Schema(description = "Detailed scoring breakdown for sub-categories")
    private Map<String, Integer> scoreBreakdown;

    @Schema(description = "Recommendations for improving safety or addressing issues")
    private java.util.List<String> recommendations;
}