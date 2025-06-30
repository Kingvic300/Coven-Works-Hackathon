package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.dto.request.WebsiteCheckRequest;
import com.bytebuilder.checker.dto.WebsiteCheckResponse;
import com.bytebuilder.checker.dto.response.WebsiteAnalysisResult;
import com.bytebuilder.checker.service.WebsiteCheckService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class WebsiteCheckController {

    private static final Logger log = LoggerFactory.getLogger(WebsiteCheckController.class);

    private final WebsiteCheckService websiteCheckService;

    @PostMapping("/check-website")
    public ResponseEntity<WebsiteCheckResponse> checkWebsite(@RequestBody WebsiteCheckRequest request) {
        String url = request.getUrl();

        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(
                    WebsiteCheckResponse.builder()
                            .url(url)
                            .description("N/A")
                            .isSecure(false)
                            .isSafeFromScams(false)
                            .isTextSafe(false)
                            .isUrlSuspicious(true)
                            .overallSafe(false)
                            .message("Invalid URL provided")
                            .analyzedAt(Instant.now())
                            .build()
            );
        }

        log.info("Received website check request for URL: {}", url);

        WebsiteAnalysisResult result = websiteCheckService.analyzeWebsite(url);

        boolean overallSafe = result.isSecure() && result.isSafeFromScams() && result.isTextSafe();

        Map<String, Object> extraInfo = new HashMap<>();
        extraInfo.put("secure", result.isSecure());
        extraInfo.put("scamStatus", result.isSafeFromScams());
        extraInfo.put("contentSafe", result.isTextSafe());

        WebsiteCheckResponse response = WebsiteCheckResponse.builder()
                .url(result.getUrl())
                .description(result.getDescription())
                .isSecure(result.isSecure())
                .isSafeFromScams(result.isSafeFromScams())
                .isTextSafe(result.isTextSafe())
                .isUrlSuspicious(!result.isSafeFromScams()) // simple logic: if not safe, suspicious
                .overallSafe(overallSafe)
                .message(generateSafetyMessage(result))
                .analyzedAt(Instant.now())
                .additionalInfo(extraInfo)
                .build();

        log.info("Website analysis completed for URL: {}, overallSafe: {}", url, response.isOverallSafe());

        return ResponseEntity.ok(response);
    }

    private String generateSafetyMessage(WebsiteAnalysisResult result) {
        if (!result.isSecure()) return "This website does not use HTTPS securely.";
        if (!result.isSafeFromScams()) return "Potential malware or phishing detected.";
        if (!result.isTextSafe()) return "Website contains suspicious or unsafe content.";
        return "Website appears safe and secure.";
    }
}
