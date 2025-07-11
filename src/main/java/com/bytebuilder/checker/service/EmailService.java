package com.bytebuilder.checker.service;

import org.springframework.scheduling.annotation.Async;

public interface EmailService {

    @Async
    void sendEmail(String to, String emailContent);
    @Async
    void sendResetPasswordEmail(String toEmail, String otp);
    
    /**
     * Check if an incoming email is spam before processing
     * @param subject Email subject
     * @param content Email content
     * @param sender Sender email address
     * @return true if spam detected, false otherwise
     */
    boolean checkIncomingEmailForSpam(String subject, String content, String sender);
}
