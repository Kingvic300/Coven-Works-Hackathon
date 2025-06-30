package com.bytebuilder.checker.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

// Advanced NLP Content Analyzer
@Component
@Slf4j
public class NLPContentAnalyzer {

    // Sentiment analysis patterns
    private static final Map<String, Double> SENTIMENT_KEYWORDS;
    static {
        SENTIMENT_KEYWORDS = new HashMap<>();
        SENTIMENT_KEYWORDS.put("urgent", -0.8);
        SENTIMENT_KEYWORDS.put("limited time", -0.7);
        SENTIMENT_KEYWORDS.put("act now", -0.9);
        SENTIMENT_KEYWORDS.put("free money", -0.9);
        SENTIMENT_KEYWORDS.put("guaranteed", -0.6);
        SENTIMENT_KEYWORDS.put("risk free", -0.5);
        SENTIMENT_KEYWORDS.put("exclusive", -0.4);
        SENTIMENT_KEYWORDS.put("winner", -0.3);
        SENTIMENT_KEYWORDS.put("claim now", -0.8);
        SENTIMENT_KEYWORDS.put("verify account", -0.7);
        SENTIMENT_KEYWORDS.put("suspended", -0.8);
        SENTIMENT_KEYWORDS.put("expired", -0.6);
        SENTIMENT_KEYWORDS.put("safe", 0.5);
        SENTIMENT_KEYWORDS.put("secure", 0.6);
        SENTIMENT_KEYWORDS.put("trusted", 0.7);
        SENTIMENT_KEYWORDS.put("verified", 0.6);
        SENTIMENT_KEYWORDS.put("official", 0.5);

    }

    // Enhanced scam detection patterns (moved from WebsiteCheckService)
    private static final Set<String> SCAM_KEYWORDS = Set.of(
            "get rich quick", "urgent action required", "free money", "win a prize",
            "verify your account now", "limited time offer", "click here to claim",
            "congratulations you've won", "act now", "exclusive deal", "guaranteed income",
            "work from home", "make money fast", "no investment required", "risk free"
    );

    // Advanced phishing patterns
    private static final List<Pattern> PHISHING_PATTERNS = Arrays.asList(
            Pattern.compile("(?i).*click\\s+here\\s+to\\s+(verify|update|confirm).*"),
            Pattern.compile("(?i).*account\\s+(suspended|locked|expired).*"),
            Pattern.compile("(?i).*within\\s+\\d+\\s+(hours?|days?).*"),
            Pattern.compile("(?i).*congratulations.*you.*(won|selected).*"),
            Pattern.compile("(?i).*\\$\\d+.*prize.*claim.*"),
            Pattern.compile("(?i).*download\\s+attachment.*"),
            Pattern.compile("(?i).*login\\s+credentials.*required.*")
    );

    // Common legitimate business terms
    private static final Set<String> LEGITIMATE_TERMS = Set.of(
            "company", "business", "service", "product", "customer", "support",
            "about us", "contact", "privacy", "terms", "policy", "help", "faq"
    );

    @Data
    @AllArgsConstructor
    public static class NLPAnalysisResult {
        private boolean isSafe;
        private double safetyScore; // 0.0 to 1.0
        private Set<String> suspiciousKeywords;
        private double sentimentScore;
        private List<String> detectedPatterns;
        private Map<String, Object> additionalMetrics;
    }

    public NLPAnalysisResult analyzeContent(String content) {
        if (!StringUtils.hasText(content)) {
            return new NLPAnalysisResult(false, 0.0, Set.of("empty_content"),
                    0.0, List.of(), Map.of());
        }

        String normalizedContent = content.toLowerCase().trim();

        // Perform various NLP analyses
        double sentimentScore = calculateSentimentScore(normalizedContent);
        // Consolidated suspicious keyword finding using both SENTIMENT_KEYWORDS (negative) and SCAM_KEYWORDS
        Set<String> suspiciousKeywords = consolidateSuspiciousKeywords(normalizedContent);
        List<String> detectedPhishingPatterns = detectPhishingPatterns(normalizedContent);
        double legitimacyScore = calculateLegitimacyScore(normalizedContent);

        // Calculate overall safety score
        double safetyScore = calculateOverallSafetyScore(
                sentimentScore, suspiciousKeywords.size(),
                detectedPhishingPatterns.size(), legitimacyScore);

        boolean isSafe = safetyScore > 0.6 && detectedPhishingPatterns.isEmpty() &&
                suspiciousKeywords.size() < 2;

        Map<String, Object> metrics = Map.of(
                "sentiment_score", sentimentScore,
                "legitimacy_score", legitimacyScore,
                "word_count", countWords(content),
                "readability_score", calculateReadabilityScore(content)
        );

        log.debug("NLP analysis completed - Safety: {}, Score: {}, Patterns: {}",
                isSafe, safetyScore, detectedPhishingPatterns.size());

        return new NLPAnalysisResult(isSafe, safetyScore, suspiciousKeywords,
                sentimentScore, detectedPhishingPatterns, metrics);
    }

    public String generateSummary(String content, int maxLength) {
        if (!StringUtils.hasText(content) || content.length() <= maxLength) {
            return content;
        }

        try {
            // Extract key sentences using simple extractive summarization
            List<String> sentences = extractSentences(content); // This is the local variable
            if (sentences.isEmpty()) {
                return content.substring(0, Math.min(maxLength, content.length()));
            }

            // Score sentences based on importance
            Map<String, Double> sentenceScores = scoreSentences(sentences, content);

            // FIX: Pass the 'sentences' list to selectTopSentences
            List<String> selectedSentences = selectTopSentences(sentenceScores, maxLength, sentences);

            // Join and clean up
            String summary = String.join(" ", selectedSentences);
            return cleanSummary(summary, maxLength);

        } catch (Exception e) {
            log.error("Error generating NLP summary", e);
            // Fallback: truncate if summarization fails
            return content.substring(0, Math.min(maxLength, content.length())) + "...";
        }
    }

    private double calculateSentimentScore(String content) {
        double score = 0.0;
        int matches = 0;

        for (Map.Entry<String, Double> entry : SENTIMENT_KEYWORDS.entrySet()) {
            if (content.contains(entry.getKey())) {
                score += entry.getValue();
                matches++;
            }
        }

        return matches > 0 ? score / matches : 0.0;
    }

    // Consolidated suspicious keywords from both sentiment and scam lists
    private Set<String> consolidateSuspiciousKeywords(String content) {
        Set<String> detected = new HashSet<>();

        // Keywords with negative sentiment from SENTIMENT_KEYWORDS
        SENTIMENT_KEYWORDS.entrySet().stream()
                .filter(entry -> entry.getValue() < -0.5)
                .filter(entry -> content.contains(entry.getKey()))
                .map(Map.Entry::getKey)
                .forEach(detected::add);

        // Keywords from the dedicated SCAM_KEYWORDS set
        SCAM_KEYWORDS.stream()
                .filter(keyword -> content.contains(keyword))
                .forEach(detected::add);

        if (!detected.isEmpty()) {
            log.warn("Detected suspicious keywords in content: {}", detected);
        }
        return detected;
    }

    private List<String> detectPhishingPatterns(String content) {
        return PHISHING_PATTERNS.stream()
                .filter(pattern -> pattern.matcher(content).find())
                .map(pattern -> "Pattern: " + pattern.pattern()) // Changed to full pattern for better logging
                .collect(Collectors.toList());
    }

    private double calculateLegitimacyScore(String content) {
        long legitimateTermsCount = LEGITIMATE_TERMS.stream()
                .filter(content::contains) // Directly filter if content contains the term
                .count();

        // Normalize score, higher for more legitimate terms. Max 1.0.
        // A simple scaling where finding all terms gives a good score.
        // Multiply by a factor (e.g., 2) to give more weight if many terms are found
        return Math.min(1.0, legitimateTermsCount / (double) LEGITIMATE_TERMS.size() * 2);
    }

    private double calculateOverallSafetyScore(double sentimentScore, int suspiciousKeywordsCount,
                                               int phishingPatternsCount, double legitimacyScore) {
        // Weighted scoring algorithm (adjust weights as needed)
        double baseScore = 0.5; // Start with a neutral score

        // Positive sentiment increases safety, negative decreases it
        baseScore += (sentimentScore * 0.3); // 30% contribution, positive or negative

        // Penalize for suspicious keywords (stronger penalty for more keywords)
        baseScore -= (suspiciousKeywordsCount * 0.15); // 15% penalty per keyword (example)

        // Strong penalty for phishing patterns
        baseScore -= (phishingPatternsCount * 0.25); // 25% penalty per pattern (example)

        // Bonus for legitimate terms
        baseScore += (legitimacyScore * 0.1); // 10% bonus

        // Clamp the score between 0.0 and 1.0
        return Math.max(0.0, Math.min(1.0, baseScore));
    }

    private List<String> extractSentences(String content) {
        return Arrays.stream(content.split("[.!?]+"))
                .map(String::trim)
                .filter(s -> s.length() > 10)
                .limit(20) // Limit for performance
                .collect(Collectors.toList());
    }

    private Map<String, Double> scoreSentences(List<String> sentences, String fullContent) {
        Map<String, Double> scores = new HashMap<>();

        // Simple TF-IDF-like scoring
        Map<String, Integer> wordFreq = buildWordFrequency(fullContent);

        for (String sentence : sentences) {
            double score = 0.0;
            String[] words = sentence.toLowerCase().split("\\s+");

            for (String word : words) {
                if (word.length() > 3 && wordFreq.containsKey(word)) {
                    score += Math.log(wordFreq.get(word) + 1);
                }
            }

            // Normalize by sentence length
            score = score / Math.max(1, words.length);

            // Bonus for first few sentences (assume they are more important)
            if (sentences.indexOf(sentence) < 3) {
                score *= 1.2;
            }

            scores.put(sentence, score);
        }

        return scores;
    }

    private Map<String, Integer> buildWordFrequency(String content) {
        Map<String, Integer> freq = new HashMap<>();
        String[] words = content.toLowerCase().replaceAll("[^a-zA-Z\\s]", "").split("\\s+");

        for (String word : words) {
            if (word.length() > 3) { // Ignore very short words
                freq.put(word, freq.getOrDefault(word, 0) + 1);
            }
        }

        return freq;
    }

    // FIX: Added 'allSentences' parameter
    private List<String> selectTopSentences(Map<String, Double> sentenceScores, int maxLength, List<String> allSentences) {
        List<String> selected = new ArrayList<>();
        int currentLength = 0;

        List<Map.Entry<String, Double>> sortedEntries = sentenceScores.entrySet().stream()
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .collect(Collectors.toList());

        for (Map.Entry<String, Double> entry : sortedEntries) {
            String sentence = entry.getKey();
            if (currentLength + sentence.length() + 1 <= maxLength) { // +1 for space
                selected.add(sentence);
                currentLength += sentence.length() + 1;
            } else {
                break; // Stop if adding next sentence exceeds max length
            }
        }
        // FIX: Use 'allSentences' for indexOf
        return selected.stream()
                .sorted(Comparator.comparingInt(allSentences::indexOf))
                .collect(Collectors.toList());
    }

    private String cleanSummary(String summary, int maxLength) {
        // Remove extra whitespace
        summary = summary.replaceAll("\\s+", " ").trim();

        if (summary.length() > maxLength) {
            // Truncate to avoid cutting off mid-word, append "..."
            summary = summary.substring(0, maxLength - 3).trim();
            int lastSpace = summary.lastIndexOf(" ");
            if (lastSpace != -1) {
                summary = summary.substring(0, lastSpace);
            }
            summary += "...";
        }

        return summary;
    }

    private int countWords(String content) {
        // Use Pattern.compile("\\s+").split(content.trim()) for robustness, but simple split is fine for common cases
        return content.trim().isEmpty() ? 0 : content.trim().split("\\s+").length;
    }

    private double calculateReadabilityScore(String content) {
        // Simple Flesch Reading Ease approximation
        int sentences = extractSentences(content).size(); // Use the existing sentence extraction
        int words = countWords(content);
        int syllables = estimateSyllables(content);

        if (sentences == 0 || words == 0) return 0.0;

        double score = 206.835 - (1.015 * (words / (double) sentences)) - (84.6 * (syllables / (double) words));
        return Math.max(0.0, Math.min(100.0, score)) / 100.0; // Normalize to 0-1
    }

    private int estimateSyllables(String content) {
        // A very simple syllable estimation (vowel count). Not highly accurate but provides a baseline.
        // For better accuracy, consider a dedicated library or more complex regex.
        String cleaned = content.toLowerCase().replaceAll("[^aeiouy]", ""); // Count vowels
        return cleaned.length();
    }
}