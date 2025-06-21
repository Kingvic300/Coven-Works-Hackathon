package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.dto.AsyncCheckResponse;
import com.bytebuilder.checker.dto.HealthCheckResponse;
import com.bytebuilder.checker.dto.WebsiteCheckRequest;
import com.bytebuilder.checker.dto.WebsiteCheckResponse;
import com.bytebuilder.checker.service.WebsiteCheckService;
import com.bytebuilder.checker.dto.WebsiteAnalysisResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;


import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Slf4j
@RestController
@RequestMapping("/api/v1/website")
@RequiredArgsConstructor
@Validated
@Tag(name = "Website Security", description = "API for checking website security and safety")
public class WebsiteCheckController {

    private final WebsiteCheckService websiteCheckService;

    @PostMapping("/check")
    @Operation(
            summary = "Analyze website security and safety",
            description = "Performs comprehensive security analysis including HTTPS validation, malware scanning, and content analysis"
    )
    @ApiResponse(responseCode = "200", description = "Analysis completed successfully")
    @ApiResponse(responseCode = "400", description = "Invalid request parameters")
    @ApiResponse(responseCode = "500", description = "Internal server error during analysis")
    public ResponseEntity<WebsiteCheckResponse> checkWebsite(
            @Valid @RequestBody WebsiteCheckRequest request) {

        log.info("Received website check request for URL: {}", request.getUrl());

        // Perform comprehensive analysis
        WebsiteAnalysisResult analysisResult = websiteCheckService.analyzeWebsite(request.getUrl());

        // Convert to response DTO
        WebsiteCheckResponse response = convertToResponse(analysisResult);

        log.info("Website analysis completed for URL: {}, safe: {}",
                request.getUrl(), response.isOverallSafe());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/check-async")
    @Operation(
            summary = "Analyze website security asynchronously",
            description = "Starts asynchronous analysis and returns immediately with a tracking ID. " +
                    "A separate endpoint would be needed to retrieve results using the tracking ID."
    )
    public ResponseEntity<AsyncCheckResponse> checkWebsiteAsync(
            @Valid @RequestBody WebsiteCheckRequest request) {

        log.info("Received async website check request for URL: {}", request.getUrl());


        CompletableFuture<WebsiteAnalysisResult> futureResult =
                websiteCheckService.analyzeWebsiteAsync(request.getUrl());

        String trackingId = generateTrackingId();

        // Simulate storing the future (in production, you'd store the result or a reference)
        // For simplicity in this example, we just return the ID.
        // A dedicated service would manage the actual async task lifecycle.
        // futureResult.thenAccept(result -> { /* Store result with trackingId */ });


        return ResponseEntity.accepted()
                .body(new AsyncCheckResponse(trackingId, "Analysis started successfully.", request.getUrl()));
    }

    @GetMapping("/check")
    @Operation(
            summary = "Quick website check via GET request",
            description = "Performs basic website safety check using URL parameter. For complex requests, use POST."
    )
    public ResponseEntity<WebsiteCheckResponse> checkWebsiteGet(
            @Parameter(description = "Website URL to check", required = true)
            @RequestParam @NotBlank String url) {

        log.info("Received GET website check request for URL: {}", url);

        // Create request object and delegate to POST method
        WebsiteCheckRequest request = new WebsiteCheckRequest();
        request.setUrl(url);

        // Reuse the POST method's logic and exception handling
        return checkWebsite(request);
    }

    @GetMapping("/health")
    @Operation(summary = "Health check endpoint")
    public ResponseEntity<HealthCheckResponse> healthCheck() {
        return ResponseEntity.ok(new HealthCheckResponse("Website Check Service is running.", true));
    }

    // Helper method to convert service result to response DTO
    private WebsiteCheckResponse convertToResponse(WebsiteAnalysisResult result) {
        return WebsiteCheckResponse.builder()
                .url(result.getUrl())
                .description(result.getDescription())
                .isSecure(result.isSecure())
                .isSafeFromScams(result.isSafeFromScams())
                .isTextSafe(result.isTextSafe())
                .isUrlSuspicious(result.isUrlSuspicious())
                .message(result.getSafetyMessage())
                .overallSafe(isOverallSafe(result))
                .analyzedAt(result.getAnalyzedAt())
                .additionalInfo(result.getAdditionalInfo())
                .build();
    }

    // Determines overall safety based on individual check results
    private boolean isOverallSafe(WebsiteAnalysisResult result) {
        return result.isSecure() &&
                result.isSafeFromScams() &&
                result.isTextSafe() &&
                !result.isUrlSuspicious(); // A suspicious URL makes it unsafe
    }

    // Generates a unique tracking ID
    private String generateTrackingId() {
        return "track_" + UUID.randomUUID().toString();
    }
}