package com.bytebuilder.checker.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LinkAnalysisResult {
    private String url;
    private boolean isSafe;
    private String safetyMessage;
    private double safetyScore;
}
