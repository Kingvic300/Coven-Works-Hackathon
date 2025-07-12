package com.bytebuilder.checker.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
@AllArgsConstructor
public class SpamAnalysisResult {
    private boolean isSpam;
    private double spamScore;
    private Set<String> detectedSpamKeywords;
    private List<String> detectedPatterns;
    private Map<String, Object> analysisMetrics;
    private String spamReason;
    private boolean isHighRisk;
    private List<LinkAnalysisResult> linkAnalysisResults;
    private String aiMessage;
}