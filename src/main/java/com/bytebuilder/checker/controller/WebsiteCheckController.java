package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.dto.WebsiteCheckRequest;
import com.bytebuilder.checker.dto.WebsiteCheckResponse;
import com.bytebuilder.checker.service.WebsiteCheckService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.cert.X509Certificate;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1")
public class WebsiteCheckController {

    @Autowired
    private WebsiteCheckService websiteCheckService;

    @PostMapping("/website/check")
    public ResponseEntity<WebsiteCheckResponse> checkWebsite(@RequestBody WebsiteCheckRequest request) {
        String url = request.getUrl();
        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new WebsiteCheckResponse("", "Invalid URL provided",
                            false, false, false, "Invalid URL provided"));
        }

        try {
            WebsiteCheckService.WebsiteAnalysisResult result = websiteCheckService.analyzeWebsite(url);

            WebsiteCheckResponse response = new WebsiteCheckResponse(
                    result.getUrl(),
                    result.getDescription(),
                    result.isSecure(),
                    result.isSafeFromScams(),
                    result.isTextSafe(),
                    result.getSafetyMessage()
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new WebsiteCheckResponse(url, "Error analyzing website",
                            false, false, false, "Error occurred during analysis"));
        }
    }

    private void handleCertificate(Optional<X509Certificate> cert) {
        X509Certificate x = cert
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));
    }
}