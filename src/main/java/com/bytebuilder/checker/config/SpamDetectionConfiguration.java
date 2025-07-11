package com.bytebuilder.checker.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "spam.detection")
public class SpamDetectionConfiguration {

    /**
     * Spam score threshold above which an email is considered spam
     */
    private double spamThreshold = 0.6;

    /**
     * High risk score threshold above which an email is considered high risk
     */
    private double highRiskThreshold = 0.8;

    /**
     * Maximum number of spam keywords before marking as spam
     */
    private int maxSpamKeywords = 3;

    /**
     * Maximum number of spam patterns before marking as spam
     */
    private int maxSpamPatterns = 2;

    /**
     * Maximum number of emails that can be checked in bulk
     */
    private int maxBulkEmails = 100;

    /**
     * Whether to enable spam detection for incoming emails
     */
    private boolean enabled = true;

    /**
     * Whether to log spam detection results
     */
    private boolean loggingEnabled = true;

    /**
     * Whether to block emails that are detected as high risk
     */
    private boolean blockHighRiskEmails = true;
} 