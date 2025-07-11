package com.bytebuilder.checker.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BulkEmailSpamCheckResponse {

    private List<EmailSpamCheckResponse> results;
    private int totalEmails;
    private int spamCount;
    private int highRiskCount;
    private double averageSpamScore;
    private Instant analyzedAt;
    private String summary;

    public String getSummary() {
        if (totalEmails == 0) {
            return "No emails analyzed";
        }
        
        return String.format("Analyzed %d emails: %d spam detected, %d high risk, average score: %.2f", 
                totalEmails, spamCount, highRiskCount, averageSpamScore);
    }
} 