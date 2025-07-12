package com.bytebuilder.checker.service;

import com.bytebuilder.checker.dto.EmailSpamCheckResponse;
import com.bytebuilder.checker.dto.BulkEmailSpamCheckResponse;
import com.bytebuilder.checker.dto.LinkAnalysisResult;
import com.bytebuilder.checker.dto.SpamAnalysisResult;
import com.bytebuilder.checker.dto.request.EmailSpamCheckRequest;
import com.bytebuilder.checker.dto.request.BulkEmailSpamCheckRequest;
import com.bytebuilder.checker.service.SpamEmailDetector;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class EmailSpamDetectionServiceImpl implements EmailSpamDetectionService {

    private final SpamEmailDetector spamEmailDetector;

    @Override
    public EmailSpamCheckResponse analyzeEmailForSpam(EmailSpamCheckRequest request) {
        log.info("Analyzing email for spam - Subject: {}, Sender: {}", 
                request.getSubject(), request.getSender());

        // Perform spam analysis
        SpamAnalysisResult analysisResult = spamEmailDetector.analyzeEmail(
                request.getSubject(),
                request.getContent(),
                request.getSender(),
                request.getRecipient()
        );

        // Build response
        EmailSpamCheckResponse response = EmailSpamCheckResponse.builder()
                .subject(request.getSubject())
                .sender(request.getSender())
                .recipient(request.getRecipient())
                .isSpam(analysisResult.isSpam())
                .isHighRisk(analysisResult.isHighRisk())
                .spamScore(analysisResult.getSpamScore())
                .detectedSpamKeywords(analysisResult.getDetectedSpamKeywords())
                .detectedPatterns(analysisResult.getDetectedPatterns())
                .spamReason(analysisResult.getSpamReason())
                .analysisMetrics(analysisResult.getAnalysisMetrics())
                .analyzedAt(Instant.now())
                .linkAnalysisResults(convertLinkAnalysisResults(analysisResult.getLinkAnalysisResults()))
                .build();

        log.info("Email spam analysis completed - IsSpam: {}, Score: {}, HighRisk: {}", 
                response.isSpam(), response.getSpamScore(), response.isHighRisk());

        return response;
    }

    private List<EmailSpamCheckResponse.LinkAnalysisResult> convertLinkAnalysisResults(
            List<LinkAnalysisResult> linkResults) {
        if (linkResults == null) {
            return new ArrayList<>();
        }

        return linkResults.stream()
                .map(link -> new EmailSpamCheckResponse.LinkAnalysisResult(
                        link.getUrl(),
                        link.isSafe(),
                        link.getSafetyMessage(),
                        link.getSafetyScore()
                ))
                .collect(java.util.stream.Collectors.toList());
    }

    @Override
    public boolean isHighPrioritySpam(String subject, String content, String sender) {
        return spamEmailDetector.isHighPrioritySpam(subject, content, sender);
    }

    @Override
    public java.util.List<String> getSpamKeywords() {
        return spamEmailDetector.getSpamKeywords();
    }

    @Override
    public BulkEmailSpamCheckResponse analyzeBulkEmailsForSpam(BulkEmailSpamCheckRequest request) {
        log.info("Analyzing {} emails for spam", request.getEmails().size());

        List<EmailSpamCheckResponse> results = new ArrayList<>();
        int spamCount = 0;
        int highRiskCount = 0;
        double totalSpamScore = 0.0;

        for (EmailSpamCheckRequest emailRequest : request.getEmails()) {
            EmailSpamCheckResponse result = analyzeEmailForSpam(emailRequest);
            results.add(result);

            if (result.isSpam()) {
                spamCount++;
            }
            if (result.isHighRisk()) {
                highRiskCount++;
            }
            totalSpamScore += result.getSpamScore();
        }

        double averageSpamScore = request.getEmails().size() > 0 ? 
                totalSpamScore / request.getEmails().size() : 0.0;

        BulkEmailSpamCheckResponse response = BulkEmailSpamCheckResponse.builder()
                .results(results)
                .totalEmails(request.getEmails().size())
                .spamCount(spamCount)
                .highRiskCount(highRiskCount)
                .averageSpamScore(averageSpamScore)
                .analyzedAt(Instant.now())
                .build();

        log.info("Bulk email spam analysis completed - Total: {}, Spam: {}, HighRisk: {}, AvgScore: {}", 
                response.getTotalEmails(), response.getSpamCount(), response.getHighRiskCount(), response.getAverageSpamScore());

        return response;
    }
} 