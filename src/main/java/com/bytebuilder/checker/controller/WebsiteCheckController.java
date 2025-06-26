package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.dto.AsyncCheckResponse;
import com.bytebuilder.checker.dto.HealthCheckResponse;
import com.bytebuilder.checker.dto.WebsiteCheckRequest;
import com.bytebuilder.checker.dto.WebsiteCheckResponse;
import com.bytebuilder.checker.dto.WebsiteAnalysisResult;
import com.bytebuilder.checker.service.WebsiteCheckService;
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
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RestController
@RequestMapping("/api/v1/website")
@RequiredArgsConstructor
@Validated
@Tag(name = "Website Security", description = "API for checking website security and safety")
public class WebsiteCheckController {

    private final WebsiteCheckService websiteCheckService;
    private final ConcurrentHashMap<String, CompletableFuture<WebsiteAnalysisResult>> asyncResults = new ConcurrentHashMap<>();

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
                    "Use the /check-async/{trackingId} endpoint to retrieve results."
    )
    @ApiResponse(responseCode = "202", description = "Analysis started successfully")
    @ApiResponse(responseCode = "400", description = "Invalid request parameters")
    public ResponseEntity<AsyncCheckResponse> checkWebsiteAsync(
            @Valid @RequestBody WebsiteCheckRequest request) {

        log.info("Received async website check request for URL: {}", request.getUrl());

        String trackingId = generateTrackingId();
        CompletableFuture<WebsiteAnalysisResult> futureResult =
                websiteCheckService.analyzeWebsiteAsync(request.getUrl());

        // Store the future for later retrieval
        asyncResults.put(trackingId, futureResult);

        return ResponseEntity.accepted()
                .body(new AsyncCheckResponse(trackingId, "Analysis started successfully.", request.getUrl()));
    }

    @GetMapping("/check-async/{trackingId}")
    @Operation(
            summary = "Retrieve asynchronous analysis result",
            description = "Fetches the result of an asynchronous website analysis using the tracking ID"
    )
    @ApiResponse(responseCode = "200", description = "Analysis result retrieved successfully")
    @ApiResponse(responseCode = "202", description = "Analysis is still in progress")
    @ApiResponse(responseCode = "404", description = "Tracking ID not found")
    public ResponseEntity<?> getAsyncResult(
            @Parameter(description = "Tracking ID of the asynchronous analysis")
            @PathVariable @NotBlank String trackingId) {

        log.info("Received request to retrieve async result for tracking ID: {}", trackingId);

        CompletableFuture<WebsiteAnalysisResult> futureResult = asyncResults.get(trackingId);

        if (futureResult == null) {
            log.warn("No analysis found for tracking ID: {}", trackingId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new AsyncCheckResponse(trackingId, "No analysis found for the given tracking ID.", null));
        }

        if (!futureResult.isDone()) {
            log.info("Analysis still in progress for tracking ID: {}", trackingId);
            return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .body(new AsyncCheckResponse(trackingId, "Analysis is still in progress.", null));
        }

        try {
            WebsiteAnalysisResult analysisResult = futureResult.get();
            WebsiteCheckResponse response = convertToResponse(analysisResult);
            log.info("Async analysis completed for tracking ID: {}, URL: {}, safe: {}",
                    trackingId, response.getUrl(), response.isOverallSafe());

            // Clean up the stored future
            asyncResults.remove(trackingId);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error retrieving async result for tracking ID: {}", trackingId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AsyncCheckResponse(trackingId, "Error retrieving analysis result.", null));
        }
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
                !result.isUrlSuspicious();
    }

    // Generates a unique tracking ID
    private String generateTrackingId() {
        return "track_" + UUID.randomUUID().toString();
    }
}