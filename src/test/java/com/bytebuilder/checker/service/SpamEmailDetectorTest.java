package com.bytebuilder.checker.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SpamEmailDetectorTest {

    @InjectMocks
    private SpamEmailDetector spamEmailDetector;

    @Test
    void testSpamEmailDetection() {
        // Test case 1: Clear spam email
        SpamEmailDetector.SpamAnalysisResult result1 = spamEmailDetector.analyzeEmail(
                "Congratulations! You've won $1,000,000!",
                "Click here to claim your prize now! Limited time offer!",
                "winner@spam.tk",
                "user@example.com"
        );

        assertTrue(result1.isSpam());
        assertTrue(result1.getSpamScore() > 0.6);
        assertFalse(result1.getDetectedSpamKeywords().isEmpty());
        assertFalse(result1.getDetectedPatterns().isEmpty());

        // Test case 2: Legitimate email
        SpamEmailDetector.SpamAnalysisResult result2 = spamEmailDetector.analyzeEmail(
                "Order Confirmation",
                "Thank you for your order. Your invoice is attached.",
                "orders@company.com",
                "customer@example.com"
        );

        assertFalse(result2.isSpam());
        assertTrue(result2.getSpamScore() < 0.6);
        assertTrue(result2.getDetectedSpamKeywords().isEmpty());
    }

    @Test
    void testHighRiskSpamDetection() {
        // Test high risk spam
        SpamEmailDetector.SpamAnalysisResult result = spamEmailDetector.analyzeEmail(
                "URGENT: Your account has been suspended",
                "Click here to verify your account immediately. Your account will be deleted within 24 hours if you don't act now!",
                "security@bank.xyz",
                "user@example.com"
        );

        assertTrue(result.isSpam());
        assertTrue(result.isHighRisk());
        assertTrue(result.getSpamScore() > 0.8);
    }

    @Test
    void testSuspiciousSenderDetection() {
        // Test suspicious sender domains
        SpamEmailDetector.SpamAnalysisResult result = spamEmailDetector.analyzeEmail(
                "Hello",
                "This is a test email",
                "sender@spam.tk",
                "user@example.com"
        );

        assertTrue(result.isSpam());
        assertTrue(result.getSpamScore() > 0.6);
    }

    @Test
    void testLegitimateEmailDetection() {
        // Test legitimate business email
        SpamEmailDetector.SpamAnalysisResult result = spamEmailDetector.analyzeEmail(
                "Welcome to our service",
                "Thank you for choosing our company. We provide excellent customer support and have clear privacy policies.",
                "welcome@company.com",
                "customer@example.com"
        );

        assertFalse(result.isSpam());
        assertTrue(result.getSpamScore() < 0.6);
        assertTrue(result.getDetectedSpamKeywords().isEmpty());
    }

    @Test
    void testSpamKeywordsDetection() {
        // Test specific spam keywords
        SpamEmailDetector.SpamAnalysisResult result = spamEmailDetector.analyzeEmail(
                "Make money fast",
                "Work from home and earn thousands. No investment required. Guaranteed income.",
                "money@example.com",
                "user@example.com"
        );

        assertTrue(result.isSpam());
        assertFalse(result.getDetectedSpamKeywords().isEmpty());
        assertTrue(result.getDetectedSpamKeywords().contains("make money fast"));
        assertTrue(result.getDetectedSpamKeywords().contains("work from home"));
        assertTrue(result.getDetectedSpamKeywords().contains("guaranteed income"));
    }

    @Test
    void testGetSpamKeywords() {
        var keywords = spamEmailDetector.getSpamKeywords();
        assertNotNull(keywords);
        assertFalse(keywords.isEmpty());
        assertTrue(keywords.contains("urgent"));
        assertTrue(keywords.contains("free money"));
        assertTrue(keywords.contains("congratulations"));
    }

    @Test
    void testHighPrioritySpamCheck() {
        // Test high priority spam detection
        boolean isHighPriority = spamEmailDetector.isHighPrioritySpam(
                "URGENT: Account Suspended",
                "Your account has been suspended. Click here to verify immediately.",
                "security@fake.tk"
        );

        assertTrue(isHighPriority);
    }

    @Test
    void testEmailWithUnsafeLinks() {
        // Test email with unsafe links
        SpamEmailDetector.SpamAnalysisResult result = spamEmailDetector.analyzeEmail(
                "Check out this amazing offer!",
                "Click here to claim your prize: https://suspicious-site.tk/claim",
                "offer@spam.com",
                "user@example.com"
        );

        assertTrue(result.isSpam());
        assertFalse(result.getLinkAnalysisResults().isEmpty());
        
        // Check if unsafe links are detected
        boolean hasUnsafeLinks = result.getLinkAnalysisResults().stream()
                .anyMatch(link -> !link.isSafe());
        assertTrue(hasUnsafeLinks);
    }

    @Test
    void testEmailWithSafeLinks() {
        // Test email with safe links
        SpamEmailDetector.SpamAnalysisResult result = spamEmailDetector.analyzeEmail(
                "Order confirmation",
                "Thank you for your order. Track your package here: https://www.amazon.com/track",
                "orders@company.com",
                "customer@example.com"
        );

        // Should not be marked as spam just because it has links
        assertFalse(result.getLinkAnalysisResults().isEmpty());
    }

    @Test
    void testUrlExtraction() {
        String content = "Check out these links: https://example.com and https://test.org";
        SpamEmailDetector.SpamAnalysisResult result = spamEmailDetector.analyzeEmail(
                "Test email",
                content,
                "test@example.com",
                "user@example.com"
        );

        assertEquals(2, result.getLinkAnalysisResults().size());
    }
} 