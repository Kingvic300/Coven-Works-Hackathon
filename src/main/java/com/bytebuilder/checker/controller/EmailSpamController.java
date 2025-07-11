package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.dto.EmailSpamCheckResponse;
import com.bytebuilder.checker.dto.BulkEmailSpamCheckResponse;
import com.bytebuilder.checker.dto.request.EmailSpamCheckRequest;
import com.bytebuilder.checker.dto.request.BulkEmailSpamCheckRequest;
import com.bytebuilder.checker.service.EmailSpamDetectionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/email")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Email Spam Detection", description = "APIs for detecting spam emails")
public class EmailSpamController {

    private final EmailSpamDetectionService emailSpamDetectionService;

    @PostMapping("/check-spam")
    @Operation(summary = "Analyze email for spam", description = "Analyzes email content, subject, and sender for spam detection")
    public ResponseEntity<EmailSpamCheckResponse> checkEmailForSpam(@RequestBody EmailSpamCheckRequest request) {
        log.info("Received email spam check request - Subject: {}, Sender: {}", 
                request.getSubject(), request.getSender());

        EmailSpamCheckResponse response = emailSpamDetectionService.analyzeEmailForSpam(request);

        log.info("Email spam analysis completed - IsSpam: {}, Score: {}", 
                response.isSpam(), response.getSpamScore());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/spam-keywords")
    @Operation(summary = "Get spam keywords", description = "Returns the list of keywords used for spam detection")
    public ResponseEntity<List<String>> getSpamKeywords() {
        List<String> keywords = emailSpamDetectionService.getSpamKeywords();
        return ResponseEntity.ok(keywords);
    }

    @PostMapping("/quick-check")
    @Operation(summary = "Quick spam check", description = "Quick check if an email is high priority spam")
    public ResponseEntity<Boolean> quickSpamCheck(@RequestBody EmailSpamCheckRequest request) {
        boolean isHighPrioritySpam = emailSpamDetectionService.isHighPrioritySpam(
                request.getSubject(), 
                request.getContent(), 
                request.getSender()
        );
        
        return ResponseEntity.ok(isHighPrioritySpam);
    }

    @PostMapping("/bulk-check")
    @Operation(summary = "Bulk email spam check", description = "Analyze multiple emails for spam detection")
    public ResponseEntity<BulkEmailSpamCheckResponse> bulkSpamCheck(@RequestBody BulkEmailSpamCheckRequest request) {
        log.info("Received bulk email spam check request for {} emails", request.getEmails().size());

        BulkEmailSpamCheckResponse response = emailSpamDetectionService.analyzeBulkEmailsForSpam(request);

        log.info("Bulk email spam analysis completed - Total: {}, Spam: {}, HighRisk: {}", 
                response.getTotalEmails(), response.getSpamCount(), response.getHighRiskCount());

        return ResponseEntity.ok(response);
    }
} 