package com.bytebuilder.checker.service;

import com.bytebuilder.checker.dto.EmailSpamCheckResponse;
import com.bytebuilder.checker.dto.BulkEmailSpamCheckResponse;
import com.bytebuilder.checker.dto.request.EmailSpamCheckRequest;
import com.bytebuilder.checker.dto.request.BulkEmailSpamCheckRequest;

public interface EmailSpamDetectionService {
    
    /**
     * Analyze an email for spam detection
     * @param request Email spam check request containing subject, content, sender, and recipient
     * @return EmailSpamCheckResponse with analysis results
     */
    EmailSpamCheckResponse analyzeEmailForSpam(EmailSpamCheckRequest request);
    
    /**
     * Quick check if an email is high priority spam
     * @param subject Email subject
     * @param content Email content
     * @param sender Sender email address
     * @return true if high priority spam, false otherwise
     */
    boolean isHighPrioritySpam(String subject, String content, String sender);
    
         /**
      * Get all spam keywords used for detection
      * @return List of spam keywords
      */
     java.util.List<String> getSpamKeywords();
     
     /**
      * Analyze multiple emails for spam detection
      * @param request Bulk email spam check request
      * @return BulkEmailSpamCheckResponse with analysis results for all emails
      */
     BulkEmailSpamCheckResponse analyzeBulkEmailsForSpam(BulkEmailSpamCheckRequest request);
} 