package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.dto.response.WebsiteCheckResponse;
import com.bytebuilder.checker.dto.request.WebsiteCheckRequest;
import com.bytebuilder.checker.dto.response.WebsiteAnalysisResult;
import com.bytebuilder.checker.service.WebsiteCheckService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class WebsiteCheckController {

    @Autowired
    private WebsiteCheckService websiteCheckService;

    @PostMapping("/check-website")
    public ResponseEntity<WebsiteCheckResponse> checkWebsite(@RequestBody WebsiteCheckRequest request) {
        String url = request.getUrl();
        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new WebsiteCheckResponse(
                            url,
                            "N/A",
                            false,
                            false,
                            false,
                            "Invalid URL provided"
                    ));
        }

        WebsiteAnalysisResult result = websiteCheckService.analyzeWebsite(url);

        WebsiteCheckResponse response = new WebsiteCheckResponse(
                result.getUrl(),
                result.getDescription(),
                result.isSecure(),
                result.isSafeFromScams(),
                result.isTextSafe(),
                result.getSafetyMessage()
        );

        return ResponseEntity.ok(response);
    }
}
