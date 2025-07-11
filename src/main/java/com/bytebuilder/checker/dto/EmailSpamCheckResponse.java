package com.bytebuilder.checker.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailSpamCheckResponse {

    private String subject;
    private String sender;
    private String recipient;
    private boolean isSpam;
    private boolean isHighRisk;
    private double spamScore; // 0.0 to 1.0
    private Set<String> detectedSpamKeywords;
    private List<String> detectedPatterns;
    private String spamReason;
    private Map<String, Object> analysisMetrics;
    private Instant analyzedAt;
    private String recommendation;
    private List<LinkAnalysisResult> linkAnalysisResults;

    public String getRecommendation() {
        if (isHighRisk) {
            return "HIGH RISK: Do not open this email. Delete immediately.";
        } else if (isSpam) {
            return "SPAM DETECTED: Exercise caution. Consider deleting this email.";
        } else {
            return "SAFE: This email appears to be legitimate.";
        }
    }

    @Data
    @AllArgsConstructor
    public static class LinkAnalysisResult {
        private String url;
        private boolean isSafe;
        private String safetyMessage;
        private double safetyScore;
    }
} 