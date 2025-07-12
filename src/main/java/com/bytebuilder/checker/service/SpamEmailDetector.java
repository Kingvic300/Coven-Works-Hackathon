package com.bytebuilder.checker.service;

import com.bytebuilder.checker.dto.LinkAnalysisResult;
import com.bytebuilder.checker.dto.SpamAnalysisResult;
import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

@Service
@Slf4j
@RequiredArgsConstructor
public class SpamEmailDetector {

    private final WebsiteCheckService websiteCheckService;
    private final AiService aiService;

    private Set<String> spamKeywords = new HashSet<>();
    private List<Pattern> spamPatterns = new ArrayList<>();
    private Set<String> legitimateTerms = new HashSet<>();
    private List<Pattern> suspiciousSenderPatterns = new ArrayList<>();

    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\d\\-._~:/?#\\[\\]@!$&'()*+,;=%]+"
    );



    @PostConstruct
    public void loadSpamData() {
        spamKeywords = loadStrings("scan_keywords.txt");
        spamPatterns = loadPatterns("spam_patterns.txt");
        legitimateTerms = loadStrings("legitimate_terms.txt");
        suspiciousSenderPatterns = loadPatterns("suspicious_senders.txt");

        log.info("Spam detection data loaded: {} keywords, {} patterns, {} legit terms, {} suspicious sender patterns",
                spamKeywords.size(), spamPatterns.size(), legitimateTerms.size(), suspiciousSenderPatterns.size());
    }

    private Set<String> loadStrings(String path) {
        Set<String> result = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ClassPathResource(path).getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    result.add(line.toLowerCase());
                }
            }
        } catch (Exception e) {
            log.error("Error reading string file '{}': {}", path, e.getMessage());
        }
        return result;
    }

    private List<Pattern> loadPatterns(String path) {
        List<Pattern> patterns = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ClassPathResource(path).getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    patterns.add(Pattern.compile(line));
                }
            }
        } catch (Exception e) {
            log.error("Error reading pattern file '{}': {}", path, e.getMessage());
        }
        return patterns;
    }

    public SpamAnalysisResult analyzeEmail(String subject, String content, String sender, String recipient) {
        if (content == null) content = "";
        if (subject == null) subject = "";

        String normalizedContent = (subject + " " + content).toLowerCase().trim();
        String normalizedSender = sender.toLowerCase().trim();

        Set<String> spamKeywordsFound = detectSpamKeywords(normalizedContent);
        List<String> spamPatternsFound = detectSpamPatterns(normalizedContent);
        boolean suspiciousSender = isSuspiciousSender(normalizedSender);
        double legitimacyScore = calculateLegitimacyScore(normalizedContent);
        double senderReputation = calculateSenderReputation(normalizedSender);
        List<LinkAnalysisResult> linkAnalysisResults = analyzeUrlsInContent(content);

        double spamScore = calculateSpamScore(
                spamKeywordsFound.size(),
                spamPatternsFound.size(),
                suspiciousSender,
                legitimacyScore,
                senderReputation,
                content.length(),
                subject.length(),
                linkAnalysisResults
        );

        boolean isSpam = spamScore > 0.6 || spamKeywordsFound.size() > 3 || spamPatternsFound.size() > 2;
        boolean isHighRisk = spamScore > 0.8 || spamKeywordsFound.size() > 5;

        Map<String, Object> metrics = Map.of(
                "spam_keywords_count", spamKeywordsFound.size(),
                "spam_patterns_count", spamPatternsFound.size(),
                "suspicious_sender", suspiciousSender,
                "legitimacy_score", legitimacyScore,
                "sender_reputation", senderReputation,
                "content_length", content.length(),
                "subject_length", subject.length(),
                "urls_found", linkAnalysisResults.size()
        );

        String spamReason = generateSpamReason(spamKeywordsFound, spamPatternsFound, suspiciousSender, spamScore, linkAnalysisResults);

        String aiMessage = aiService.chat("""
                You are an email security analyst.
                Analyze this email and explain why it is %s:

                Subject: %s
                Content: %s
                Sender: %s

                Spam Score: %.2f
                Keywords: %s
                Patterns: %s
                Suspicious Sender: %s
                URLs: %d (Unsafe: %d)
                """
                .formatted(
                        isSpam ? "SPAM" : "NOT SPAM",
                        subject,
                        content,
                        sender,
                        spamScore,
                        String.join(", ", spamKeywordsFound),
                        String.join(", ", spamPatternsFound),
                        suspiciousSender ? "Yes" : "No",
                        linkAnalysisResults.size(),
                        linkAnalysisResults.stream().filter(l -> !l.isSafe()).count()
                ));

        return new SpamAnalysisResult(isSpam, spamScore, spamKeywordsFound,
                spamPatternsFound, metrics, spamReason, isHighRisk, linkAnalysisResults, aiMessage);
    }

    private Set<String> detectSpamKeywords(String content) {
        Set<String> detected = new HashSet<>();
        for (String keyword : spamKeywords) {
            if (content.contains(keyword.toLowerCase())) {
                detected.add(keyword);
            }
        }
        return detected;
    }

    private List<String> detectSpamPatterns(String content) {
        List<String> detected = new ArrayList<>();
        for (Pattern pattern : spamPatterns) {
            if (pattern.matcher(content).find()) {
                detected.add("Pattern: " + pattern.pattern());
            }
        }
        return detected;
    }

    private boolean isSuspiciousSender(String sender) {
        for (Pattern pattern : suspiciousSenderPatterns) {
            if (pattern.matcher(sender).find()) {
                return true;
            }
        }
        return false;
    }

    private double calculateLegitimacyScore(String content) {
        long count = legitimateTerms.stream().filter(content::contains).count();
        return Math.min(1.0, count / (double) legitimateTerms.size() * 2);
    }

    private double calculateSenderReputation(String sender) {
        if (sender.contains("@gmail.com") || sender.contains("@yahoo.com") ||
                sender.contains("@hotmail.com") || sender.contains("@outlook.com")) {
            return 0.8;
        }
        if (sender.contains("@") && sender.contains(".")) {
            return 0.5;
        }
        return 0.1;
    }

    private double calculateSpamScore(int keywordCount, int patternCount, boolean suspiciousSender,
                                      double legitimacyScore, double senderReputation, int contentLength, int subjectLength,
                                      List<LinkAnalysisResult> linkAnalysisResults) {
        double score = 0.0;
        score += (keywordCount * 0.125);
        score += (patternCount * 0.1);
        if (suspiciousSender) score += 0.15;
        score += (1.0 - senderReputation) * 0.075;
        score += (1.0 - legitimacyScore) * 0.15;
        score += calculateUrlSpamScore(linkAnalysisResults);
        if (contentLength < 50) score += 0.025;
        if (subjectLength > 100) score += 0.025;
        return Math.min(1.0, score);
    }

    private double calculateUrlSpamScore(List<LinkAnalysisResult> results) {
        if (results.isEmpty()) return 0.0;
        double score = 0.0;
        int unsafeCount = 0;
        for (LinkAnalysisResult r : results) {
            if (!r.isSafe()) {
                unsafeCount++;
                score += 0.2;
            }
        }
        if (unsafeCount > results.size() / 2) score += 0.1;
        return Math.min(0.2, score);
    }

    private List<LinkAnalysisResult> analyzeUrlsInContent(String content) {
        List<LinkAnalysisResult> results = new ArrayList<>();
        Set<String> urls = extractUrlsFromContent(content);
        for (String url : urls) {
            try {
                var websiteResult = websiteCheckService.analyzeWebsite(url);
                boolean isSafe = websiteResult.isSecure() && websiteResult.isSafeFromScams() && websiteResult.isTextSafe();
                results.add(new LinkAnalysisResult(url, isSafe, websiteResult.getSafetyMessage(), isSafe ? 0.8 : 0.2));
            } catch (Exception e) {
                results.add(new LinkAnalysisResult(url, false, "URL analysis failed: " + e.getMessage(), 0.0));
            }
        }
        return results;
    }

    private Set<String> extractUrlsFromContent(String content) {
        Set<String> urls = new HashSet<>();
        java.util.regex.Matcher matcher = URL_PATTERN.matcher(content);
        while (matcher.find()) {
            String url = matcher.group().replaceAll("[.,;!?]+$", "");
            urls.add(url);
        }
        return urls;
    }

    private String generateSpamReason(
            Set<String> keywords, List<String> patterns,
            boolean suspiciousSender, double spamScore,
            List<LinkAnalysisResult> linkAnalysisResults
    ) {
        List<String> reasons = new ArrayList<>();
        if (!keywords.isEmpty()) reasons.add("Contains suspicious keywords: " + String.join(", ", keywords));
        if (!patterns.isEmpty()) reasons.add("Matches spam patterns");
        if (suspiciousSender) reasons.add("Suspicious sender address");
        int unsafeCount = (int) linkAnalysisResults.stream().filter(link -> !link.isSafe()).count();
        if (unsafeCount > 0) reasons.add("Contains " + unsafeCount + " unsafe link(s)");
        if (spamScore > 0.8) reasons.add("High spam probability score");
        return reasons.isEmpty() ? "No specific spam indicators detected" : String.join("; ", reasons);
    }

    public boolean isHighPrioritySpam(String subject, String content, String sender) {
        return analyzeEmail(subject, content, sender, "").isHighRisk();
    }

    public List<String> getSpamKeywords() {
        return new ArrayList<>(spamKeywords);
    }
}
