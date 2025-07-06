package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.dto.request.WebsiteCheckRequest;
import com.bytebuilder.checker.dto.WebsiteCheckResponse;
import com.bytebuilder.checker.dto.response.WebsiteAnalysisResult;
import com.bytebuilder.checker.exception.NoUrlPassedException;
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
            log.error("Received empty URL in request");
            throw new NoUrlPassedException("No URL provided for website check.");
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
                .isUrlSuspicious(!result.isSafeFromScams())
                .overallSafe(overallSafe)
                .message(result.getSafetyMessage())
                .analyzedAt(Instant.now())
                .additionalInfo(extraInfo)
                .build();

        log.info("Website analysis completed for URL: {}, overallSafe: {}", url, response.isOverallSafe());

        return ResponseEntity.ok(response);
    }
}
