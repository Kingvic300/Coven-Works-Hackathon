package com.bytebuilder.checker.controller;


import com.bytebuilder.checker.dto.WebsiteCheckRequest;
import com.bytebuilder.checker.dto.WebsiteCheckResponse;
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
                    .body(new WebsiteCheckResponse(url, false, false, "Invalid URL provided"));
        }

        boolean isSecure = websiteCheckService.isSecure(url);
        boolean isSafe = websiteCheckService.isSafeFromScams(url);
        String description = websiteCheckService.analyzeWebsite(url).getDescription();
        System.out.println(description);
        String message = isSecure && isSafe ? "Website is likely safe" : "Website is potentially unsafe";

        WebsiteCheckResponse response = new WebsiteCheckResponse(url, isSecure, isSafe, message);
        return ResponseEntity.ok(response);
    }
}
