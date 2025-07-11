package com.bytebuilder.checker.service;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

@Service
@Slf4j
@RequiredArgsConstructor
public class SpamEmailDetector {

    private final WebsiteCheckService websiteCheckService;

    // Spam keywords and patterns
    private static final Set<String> SPAM_KEYWORDS = Set.of(
            "urgent", "limited time", "act now", "free money", "win a prize",
            "congratulations", "you've won", "claim now", "exclusive offer",
            "guaranteed income", "work from home", "make money fast",
            "no investment required", "risk free", "double your money",
            "get rich quick", "earn thousands", "secret formula",
            "miracle cure", "lose weight fast", "enlarge", "viagra",
            "lottery winner", "inheritance", "unclaimed funds",
            "bank transfer", "urgent action required", "account suspended",
            "verify your account", "update your information", "final notice",
            "one-time offer", "limited availability", "as seen on tv",
            "be your own boss", "financial freedom", "debt consolidation"
    );

    // Suspicious email patterns
    private static final List<Pattern> SPAM_PATTERNS = Arrays.asList(
            Pattern.compile("(?i).*\\$\\d+.*prize.*claim.*"),
            Pattern.compile("(?i).*click\\s+here\\s+to\\s+(verify|update|confirm).*"),
            Pattern.compile("(?i).*account\\s+(suspended|locked|expired).*"),
            Pattern.compile("(?i).*within\\s+\\d+\\s+(hours?|days?).*"),
            Pattern.compile("(?i).*congratulations.*you.*(won|selected).*"),
            Pattern.compile("(?i).*download\\s+attachment.*"),
            Pattern.compile("(?i).*login\\s+credentials.*required.*"),
            Pattern.compile("(?i).*bank\\s+transfer.*urgent.*"),
            Pattern.compile("(?i).*inheritance.*unclaimed.*"),
            Pattern.compile("(?i).*lottery.*winner.*"),
            Pattern.compile("(?i).*miracle.*cure.*"),
            Pattern.compile("(?i).*weight\\s+loss.*guaranteed.*"),
            Pattern.compile("(?i).*enlarge.*penis.*"),
            Pattern.compile("(?i).*viagra.*cialis.*"),
            Pattern.compile("(?i).*debt\\s+consolidation.*"),
            Pattern.compile("(?i).*refinance.*loan.*"),
            Pattern.compile("(?i).*credit\\s+card.*offer.*"),
            Pattern.compile("(?i).*investment.*opportunity.*"),
            Pattern.compile("(?i).*crypto.*currency.*investment.*"),
            Pattern.compile("(?i).*nigerian.*prince.*")
    );

    // Suspicious sender patterns
    private static final List<Pattern> SUSPICIOUS_SENDER_PATTERNS = Arrays.asList(
            Pattern.compile("(?i).*@.*\\.(tk|ml|ga|cf|gq)$"), // Free domains often used for spam
            Pattern.compile("(?i).*@.*\\.(xyz|top|site|online)$"), // New TLDs often used for spam
            Pattern.compile("(?i).*@.*\\.(info|biz)$"), // Less trusted TLDs
            Pattern.compile("(?i).*[0-9]{8,}@.*"), // Many numbers in email
            Pattern.compile("(?i).*[a-z]{20,}@.*"), // Very long random strings
            Pattern.compile("(?i).*support.*@.*"), // Generic support emails
            Pattern.compile("(?i).*noreply.*@.*"), // No-reply emails
            Pattern.compile("(?i).*admin.*@.*"), // Admin emails
            Pattern.compile("(?i).*service.*@.*"), // Service emails
            Pattern.compile("(?i).*info.*@.*") // Info emails
    );

    // Legitimate business terms (reduce spam score)
    private static final Set<String> LEGITIMATE_TERMS = Set.of(
            "company", "business", "service", "product", "customer", "support",
            "about us", "contact", "privacy", "terms", "policy", "help", "faq",
            "order", "invoice", "receipt", "confirmation", "welcome", "thank you",
            "newsletter", "update", "notification", "reminder", "appointment"
    );

    // URL extraction pattern
    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\d\\-._~:/?#\\[\\]@!$&'()*+,;=%]+"
    );

    @Data
    @AllArgsConstructor
    public static class SpamAnalysisResult {
        private boolean isSpam;
        private double spamScore; // 0.0 to 1.0
        private Set<String> detectedSpamKeywords;
        private List<String> detectedPatterns;
        private Map<String, Object> analysisMetrics;
        private String spamReason;
        private boolean isHighRisk;
        private List<LinkAnalysisResult> linkAnalysisResults;
    }

    @Data
    @AllArgsConstructor
    public static class LinkAnalysisResult {
        private String url;
        private boolean isSafe;
        private String safetyMessage;
        private double safetyScore;
    }

    public SpamAnalysisResult analyzeEmail(String subject, String content, String sender, String recipient) {
        if (content == null) content = "";
        if (subject == null) subject = "";

        String normalizedContent = (subject + " " + content).toLowerCase().trim();
        String normalizedSender = sender.toLowerCase().trim();

        // Perform various spam analyses
        Set<String> spamKeywords = detectSpamKeywords(normalizedContent);
        List<String> spamPatterns = detectSpamPatterns(normalizedContent);
        boolean suspiciousSender = isSuspiciousSender(normalizedSender);
        double legitimacyScore = calculateLegitimacyScore(normalizedContent);
        double senderReputation = calculateSenderReputation(normalizedSender);

        // Extract and analyze URLs in the email content
        List<LinkAnalysisResult> linkAnalysisResults = analyzeUrlsInContent(content);

        // Calculate overall spam score
        double spamScore = calculateSpamScore(
                spamKeywords.size(),
                spamPatterns.size(),
                suspiciousSender,
                legitimacyScore,
                senderReputation,
                content.length(),
                subject.length(),
                linkAnalysisResults
        );

        boolean isSpam = spamScore > 0.6 || spamKeywords.size() > 3 || spamPatterns.size() > 2;
        boolean isHighRisk = spamScore > 0.8 || spamKeywords.size() > 5;

        Map<String, Object> metrics = Map.of(
                "spam_keywords_count", spamKeywords.size(),
                "spam_patterns_count", spamPatterns.size(),
                "suspicious_sender", suspiciousSender,
                "legitimacy_score", legitimacyScore,
                "sender_reputation", senderReputation,
                "content_length", content.length(),
                "subject_length", subject.length(),
                "urls_found", linkAnalysisResults.size()
        );

        String spamReason = generateSpamReason(spamKeywords, spamPatterns, suspiciousSender, spamScore, linkAnalysisResults);

        log.debug("Spam analysis completed - Score: {}, Keywords: {}, Patterns: {}, URLs: {}", 
                spamScore, spamKeywords.size(), spamPatterns.size(), linkAnalysisResults.size());

        return new SpamAnalysisResult(isSpam, spamScore, spamKeywords, 
                spamPatterns, metrics, spamReason, isHighRisk, linkAnalysisResults);
    }

    private Set<String> detectSpamKeywords(String content) {
        Set<String> detected = new HashSet<>();
        
        for (String keyword : SPAM_KEYWORDS) {
            if (content.contains(keyword.toLowerCase())) {
                detected.add(keyword);
            }
        }

        if (!detected.isEmpty()) {
            log.warn("Detected spam keywords in email: {}", detected);
        }
        
        return detected;
    }

    private List<String> detectSpamPatterns(String content) {
        List<String> detected = new ArrayList<>();
        
        for (Pattern pattern : SPAM_PATTERNS) {
            if (pattern.matcher(content).find()) {
                detected.add("Pattern: " + pattern.pattern());
            }
        }

        if (!detected.isEmpty()) {
            log.warn("Detected spam patterns in email: {}", detected);
        }
        
        return detected;
    }

    private boolean isSuspiciousSender(String sender) {
        for (Pattern pattern : SUSPICIOUS_SENDER_PATTERNS) {
            if (pattern.matcher(sender).find()) {
                log.warn("Suspicious sender detected: {}", sender);
                return true;
            }
        }
        return false;
    }

    private double calculateLegitimacyScore(String content) {
        long legitimateTermsCount = LEGITIMATE_TERMS.stream()
                .filter(content::contains)
                .count();

        // Normalize score, higher for more legitimate terms
        return Math.min(1.0, legitimateTermsCount / (double) LEGITIMATE_TERMS.size() * 2);
    }

    private double calculateSenderReputation(String sender) {
        // Simple reputation scoring based on domain and format
        if (sender.contains("@gmail.com") || sender.contains("@yahoo.com") || 
            sender.contains("@hotmail.com") || sender.contains("@outlook.com")) {
            return 0.8; // Well-known providers
        }
        
        if (sender.contains("@") && sender.contains(".")) {
            return 0.5; // Valid email format
        }
        
        return 0.1; // Suspicious format
    }

    private double calculateSpamScore(int keywordCount, int patternCount, boolean suspiciousSender,
                                   double legitimacyScore, double senderReputation, int contentLength, int subjectLength,
                                   List<LinkAnalysisResult> linkAnalysisResults) {
        double score = 0.0;
        
        // Keyword weight (25%)
        score += (keywordCount * 0.125);
        
        // Pattern weight (20%)
        score += (patternCount * 0.1);
        
        // Sender reputation (15%)
        if (suspiciousSender) {
            score += 0.15;
        }
        score += (1.0 - senderReputation) * 0.075;
        
        // Content analysis (15%)
        score += (1.0 - legitimacyScore) * 0.15;
        
        // URL analysis (20%)
        score += calculateUrlSpamScore(linkAnalysisResults);
        
        // Length analysis (5%)
        if (contentLength < 50) score += 0.025; // Very short content
        if (subjectLength > 100) score += 0.025; // Very long subject
        
        return Math.min(1.0, score);
    }

    private double calculateUrlSpamScore(List<LinkAnalysisResult> linkAnalysisResults) {
        if (linkAnalysisResults.isEmpty()) {
            return 0.0; // No URLs found
        }

        double totalScore = 0.0;
        int unsafeUrls = 0;

        for (LinkAnalysisResult linkResult : linkAnalysisResults) {
            if (!linkResult.isSafe()) {
                unsafeUrls++;
                totalScore += 0.2; // Each unsafe URL adds significant weight
            }
        }

        // If more than half of URLs are unsafe, add extra penalty
        if (unsafeUrls > linkAnalysisResults.size() / 2) {
            totalScore += 0.1;
        }

        return Math.min(0.2, totalScore); // Cap URL score at 20%
    }

    private List<LinkAnalysisResult> analyzeUrlsInContent(String content) {
        List<LinkAnalysisResult> results = new ArrayList<>();
        
        if (content == null || content.trim().isEmpty()) {
            return results;
        }

        // Extract URLs from content
        Set<String> urls = extractUrlsFromContent(content);
        
        log.info("Found {} URLs in email content", urls.size());

        for (String url : urls) {
            try {
                LinkAnalysisResult result = analyzeUrl(url);
                results.add(result);
                
                if (!result.isSafe()) {
                    log.warn("Unsafe URL detected in email: {} - {}", url, result.getSafetyMessage());
                }
            } catch (Exception e) {
                log.error("Error analyzing URL {}: {}", url, e.getMessage());
                // Add a default unsafe result for failed analysis
                results.add(new LinkAnalysisResult(url, false, "URL analysis failed", 0.0));
            }
        }

        return results;
    }

    private Set<String> extractUrlsFromContent(String content) {
        Set<String> urls = new HashSet<>();
        java.util.regex.Matcher matcher = URL_PATTERN.matcher(content);
        
        while (matcher.find()) {
            String url = matcher.group();
            // Clean up the URL (remove trailing punctuation)
            url = url.replaceAll("[.,;!?]+$", "");
            urls.add(url);
        }
        
        return urls;
    }

    private LinkAnalysisResult analyzeUrl(String url) {
        try {
            // Use the existing website check service to analyze the URL
            var websiteResult = websiteCheckService.analyzeWebsite(url);
            
            boolean isSafe = websiteResult.isSecure() && websiteResult.isSafeFromScams() && websiteResult.isTextSafe();
            double safetyScore = isSafe ? 0.8 : 0.2; // Simple scoring based on website analysis
            
            return new LinkAnalysisResult(url, isSafe, websiteResult.getSafetyMessage(), safetyScore);
            
        } catch (Exception e) {
            log.error("Error analyzing URL {}: {}", url, e.getMessage());
            // Return unsafe result for URLs that can't be analyzed
            return new LinkAnalysisResult(url, false, "URL analysis failed: " + e.getMessage(), 0.0);
        }
    }

    private String generateSpamReason(Set<String> keywords, List<String> patterns, 
                                    boolean suspiciousSender, double spamScore, List<LinkAnalysisResult> linkAnalysisResults) {
        List<String> reasons = new ArrayList<>();
        
        if (!keywords.isEmpty()) {
            reasons.add("Contains suspicious keywords: " + String.join(", ", keywords));
        }
        
        if (!patterns.isEmpty()) {
            reasons.add("Matches spam patterns");
        }
        
        if (suspiciousSender) {
            reasons.add("Suspicious sender address");
        }
        
        // Add URL-related reasons
        if (!linkAnalysisResults.isEmpty()) {
            int unsafeUrls = (int) linkAnalysisResults.stream().filter(link -> !link.isSafe()).count();
            if (unsafeUrls > 0) {
                reasons.add("Contains " + unsafeUrls + " unsafe link(s)");
            }
        }
        
        if (spamScore > 0.8) {
            reasons.add("High spam probability score");
        }
        
        if (reasons.isEmpty()) {
            return "No specific spam indicators detected";
        }
        
        return String.join("; ", reasons);
    }

    public boolean isHighPrioritySpam(String subject, String content, String sender) {
        SpamAnalysisResult result = analyzeEmail(subject, content, sender, "");
        return result.isHighRisk();
    }

    public List<String> getSpamKeywords() {
        return new ArrayList<>(SPAM_KEYWORDS);
    }
} 