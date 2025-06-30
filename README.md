Website Checker
Overview
Website Checker is a Spring Boot application designed to analyze websites for security and content, optimized for social media and e-commerce platforms. It validates website safety through HTTPS certificate checks, VirusTotal API scans, suspicious URL pattern detection, and advanced NLP content analysis. The WebsiteCheckService and NLPContentAnalyzer handle core analysis, while the WebsiteCheckController provides REST API endpoints for synchronous and asynchronous checks, async result retrieval, quick GET-based checks, and health monitoring. Results are returned as WebsiteCheckResponse for synchronous and async result checks, AsyncCheckResponse for asynchronous submissions, and HealthCheckResponse for health status, ensuring secure user inflows and outflows for shared links and transactions.
Features

REST API Endpoints:
POST /api/v1/website/check: Synchronous analysis
POST /api/v1/website/check-async: Asynchronous analysis with tracking ID
GET /api/v1/website/check-async/{trackingId}: Retrieve async analysis results
GET /api/v1/website/check?url={url}: Quick check
GET /api/v1/website/health: Health check


HTTPS Validation: Verifies SSL/TLS certificates using OkHttp.
Scam Detection: Uses VirusTotal API for malware and phishing scans.
Suspicious URL Patterns: Detects risky URLs (e.g., IP addresses, typosquatting).
NLP Content Analysis:
Sentiment analysis, scam keyword detection, phishing pattern matching.
Legitimacy scoring and extractive summarization.


Asynchronous Processing: Uses CompletableFuture for non-blocking analysis, with in-memory storage for results.
Configurable Settings: Customizable timeouts, polling delays, and max attempts.
OpenAPI Documentation: Swagger UI for API exploration.
Logging: SLF4J with Logback for monitoring.

Prerequisites

Java: JDK 17 or higher
Maven: 3.8.6 or higher
Spring Boot: 3.1.0 or higher
VirusTotal API Key: Obtain from VirusTotal
IDE: IntelliJ IDEA, Eclipse, or VS Code (optional)

Setup

Clone the Repository:
git clone https://github.com/your-repo/website-checker.git
cd website-checker


Configure Application Properties:

Edit src/main/resources/application.properties:virustotal.api.key=your-virustotal-api-key
virustotal.poll.delay=3000
virustotal.max.attempts=5
content.scraping.timeout=10000
springdoc.api-docs.path=/api-docs
springdoc.swagger-ui.path=/swagger-ui.html


Replace your-virustotal-api-key with your VirusTotal API key.


Install Dependencies:

Update pom.xml:<dependencies>
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-web</artifactId>
<version>3.1.0</version>
</dependency>
<dependency>
<groupId>org.springdoc</groupId>
<artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
<version>2.1.0</version>
</dependency>
<dependency>
<groupId>com.fasterxml.jackson.core</groupId>
<artifactId>jackson-databind</artifactId>
<version>2.15.2</version>
</dependency>
<dependency>
<groupId>com.squareup.okhttp3</groupId>
<artifactId>okhttp</artifactId>
<version>4.10.0</version>
</dependency>
<dependency>
<groupId>com.google.code.gson</groupId>
<artifactId>gson</artifactId>
<version>2.10.1</version>
</dependency>
<dependency>
<groupId>org.jsoup</groupId>
<artifactId>jsoup</artifactId>
<version>1.17.2</version>
</dependency>
<dependency>
<groupId>org.slf4j</groupId>
<artifactId>slf4j-api</artifactId>
<version>2.0.9</version>
</dependency>
<dependency>
<groupId>ch.qos.logback</groupId>
<artifactId>logback-classic</artifactId>
<version>1.4.11</version>
</dependency>
<dependency>
<groupId>org.projectlombok</groupId>
<artifactId>lombok</artifactId>
<version>1.18.30</version>
<scope>provided</scope>
</dependency>
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-validation</artifactId>
<version>3.1.0</version>
</dependency>
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-test</artifactId>
<version>3.1.0</version>
<scope>test</scope>
</dependency>
<dependency>
<groupId>org.mockito</groupId>
<artifactId>mockito-core</artifactId>
<version>5.5.0</version>
<scope>test</scope>
</dependency>
<dependency>
<groupId>org.junit.jupiter</groupId>
<artifactId>junit-jupiter</artifactId>
<version>5.9.3</version>
<scope>test</scope>
</dependency>
</dependencies>


Run:mvn clean install




Configure Spring Beans:

Create src/main/java/com/bytebuilder/checker/config/AppConfig.java:package com.bytebuilder.checker.config;

import com.google.gson.Gson;
import com.bytebuilder.checker.service.NLPContentAnalyzer;
import okhttp3.OkHttpClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
@Bean
public OkHttpClient okHttpClient() {
return new OkHttpClient.Builder().build();
}

    @Bean
    public Gson gson() {
        return new Gson();
    }

    @Bean
    public NLPContentAnalyzer nlpContentAnalyzer() {
        return new NLPContentAnalyzer();
    }
}




Create DTOs:

src/main/java/com/bytebuilder/checker/dto/WebsiteAnalysisResult.java:package com.bytebuilder.checker.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebsiteAnalysisResult {
private String url;
private String description;
private boolean isSecure;
private boolean isSafeFromScams;
private boolean isTextSafe;
private boolean isUrlSuspicious;
private String safetyMessage;
private Map<String, Object> additionalInfo;
private Instant analyzedAt;
}


src/main/java/com/bytebuilder/checker/dto/WebsiteCheckRequest.java:package com.bytebuilder.checker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Request for website analysis")
public class WebsiteCheckRequest {
@NotBlank
@Schema(description = "URL to analyze", example = "https://example.com")
private String url;
}


src/main/java/com/bytebuilder/checker/dto/WebsiteCheckResponse.java:package com.bytebuilder.checker.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Website security and safety analysis result")
public class WebsiteCheckResponse {
@Schema(description = "Analyzed URL", example = "https://example.com")
private String url;

    @Schema(description = "Website description extracted from content")
    private String description;

    @Schema(description = "Whether the website uses HTTPS securely")
    private boolean isSecure;

    @Schema(description = "Whether the website is safe from malware/scams based on external scanners")
    private boolean isSafeFromScams;

    @Schema(description = "Whether the website content appears safe (no suspicious keywords)")
    private boolean isTextSafe;

    @Schema(description = "Whether the URL itself appears suspicious")
    private boolean isUrlSuspicious;

    @Schema(description = "Overall safety assessment (true if all checks pass)")
    private boolean overallSafe;

    @Schema(description = "Human-readable safety message")
    private String message;

    @Schema(description = "When the analysis was performed")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
    private Instant analyzedAt;

    @Schema(description = "Additional technical information about the analysis (e.g., analysis time, specific detected keywords)")
    private Map<String, Object> additionalInfo;

    @Schema(description = "Legacy field: true if website is safe from scams/malware, false otherwise.")
    public boolean isSafe() {
        return isSafeFromScams;
    }
}


src/main/java/com/bytebuilder/checker/dto/AsyncCheckResponse.java:package com.bytebuilder.checker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response for asynchronous website check requests")
public class AsyncCheckResponse {
@Schema(description = "Unique identifier for tracking the asynchronous analysis")
private String trackingId;

    @Schema(description = "Status message for the asynchronous request")
    private String message;

    @Schema(description = "The URL that was submitted for analysis")
    private String url;
}


src/main/java/com/bytebuilder/checker/dto/HealthCheckResponse.java:package com.bytebuilder.checker.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response for service health check")
public class HealthCheckResponse {
@Schema(description = "Status message", example = "Website Check Service is running.")
private String message;

    @Schema(description = "True if the service is healthy, false otherwise")
    private boolean healthy;
}




Build and Run:

Build:mvn package


Run:mvn spring-boot:run


Access:
API: http://localhost:8080/api/v1/website
Swagger UI: http://localhost:8080/swagger-ui.html





Project Structure
Checker/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/bytebuilder/checker/
│   │   │       ├── config/
│   │   │       │   └── AppConfig.java
│   │   │       ├── controller/
│   │   │       │   └── WebsiteCheckController.java
│   │   │       ├── dto/
│   │   │       │   ├── WebsiteAnalysisResult.java
│   │   │       │   ├── WebsiteCheckRequest.java
│   │   │       │   ├── WebsiteCheckResponse.java
│   │   │       │   ├── AsyncCheckResponse.java
│   │   │       │   └── HealthCheckResponse.java
│   │   │       ├── service/
│   │   │       │   ├── WebsiteCheckService.java
│   │   │       │   └── NLPContentAnalyzer.java
│   │   │       └── CheckerApplication.java
│   │   └── resources/
│   │       └── application.properties
│   └── test/
│       └── java/
│           └── com/bytebuilder/checker/
│               ├── controller/
│               │   └── WebsiteCheckControllerTest.java
│               └── service/
│                   ├── WebsiteCheckServiceTest.java
│                   └── NLPContentAnalyzerTest.java
├── pom.xml
└── README.md

Usage
API Endpoints

POST /api/v1/website/check:
Request: WebsiteCheckRequest with url
Response: WebsiteCheckResponse with analysis results
Example:curl -X POST http://localhost:8080/api/v1/website/check \
-H "Content-Type: application/json" \
-d '{"url":"https://example.com"}'

Response:{
"url": "https://example.com",
"description": "A sample website for testing purposes.",
"isSecure": true,
"isSafeFromScams": true,
"isTextSafe": true,
"isUrlSuspicious": false,
"overallSafe": true,
"message": "Website appears to be safe.",
"analyzedAt": "2025-06-26T20:52:00.000Z",
"additionalInfo": {
"analysisTimeMs": 1234,
"suspiciousKeywordsDetected": [],
"sentiment_score": 0.6,
"legitimacy_score": 0.8,
"word_count": 150,
"readability_score": 0.7
},
"isSafe": true
}




POST /api/v1/website/check-async:
Request: WebsiteCheckRequest with url
Response: AsyncCheckResponse with tracking ID
Example:curl -X POST http://localhost:8080/api/v1/website/check-async \
-H "Content-Type: application/json" \
-d '{"url":"https://example.com"}'

Response:{
"trackingId": "track_123e4567-e89b-12d3-a456-426614174000",
"message": "Analysis started successfully.",
"url": "https://example.com"
}




GET /api/v1/website/check-async/{trackingId}:
Retrieve async analysis result
Example:curl http://localhost:8080/api/v1/website/check-async/track_123e4567-e89b-12d3-a456-426614174000

Response (if complete):{
"url": "https://example.com",
"description": "A sample website for testing purposes.",
"isSecure": true,
"isSafeFromScams": true,
"isTextSafe": true,
"isUrlSuspicious": false,
"overallSafe": true,
"message": "Website appears to be safe.",
"analyzedAt": "2025-06-26T20:52:00.000Z",
"additionalInfo": {
"analysisTimeMs": 1234,
"suspiciousKeywordsDetected": [],
"sentiment_score": 0.6,
"legitimacy_score": 0.8,
"word_count": 150,
"readability_score": 0.7
},
"isSafe": true
}

Response (if in progress):{
"trackingId": "track_123e4567-e89b-12d3-a456-426614174000",
"message": "Analysis is still in progress.",
"url": null
}

Response (if not found):{
"trackingId": "track_123e4567-e89b-12d3-a456-426614174000",
"message": "No analysis found for the given tracking ID.",
"url": null
}




GET /api/v1/website/check?url={url}:
Quick check using URL parameter
Example:curl "http://localhost:8080/api/v1/website/check?url=https://example.com"




GET /api/v1/website/health:
Health check
Example:curl http://localhost:8080/api/v1/website/health

Response:{
"message": "Website Check Service is running.",
"healthy": true
}





Social Media and E-commerce Integration

Social Media:
Validate shared links:RestTemplate restTemplate = new RestTemplate();
WebsiteCheckResponse response = restTemplate.postForObject(
"http://localhost:8080/api/v1/website/check",
new WebsiteCheckRequest("https://example.com"),
WebsiteCheckResponse.class
);
if (response.isOverallSafe()) {
displayLink(response.getDescription());
} else {
blockLink(response.getMessage());
}




E-commerce:
Secure payment gateways:RestTemplate restTemplate = new RestTemplate();
AsyncCheckResponse asyncResponse = restTemplate.postForObject(
"http://localhost:8080/api/v1/website/check-async",
new WebsiteCheckRequest(paymentGatewayUrl),
AsyncCheckResponse.class
);
// Poll for result
WebsiteCheckResponse result = restTemplate.getForObject(
"http://localhost:8080/api/v1/website/check-async/" + asyncResponse.getTrackingId(),
WebsiteCheckResponse.class
);
if (result != null && result.isOverallSafe()) {
proceedWithPayment();
}





Swagger UI
Access API documentation at http://localhost:8080/swagger-ui.html.
Testing
Unit tests for WebsiteCheckService, NLPContentAnalyzer, and WebsiteCheckController use JUnit 5, Mockito, and Spring Boot Test, covering:

HTTPS validation, VirusTotal scans, URL pattern detection
NLP analysis (sentiment, scam keywords, phishing patterns, summarization)
API endpoints (synchronous, asynchronous, async result retrieval, GET, health check)

Running Tests
mvn test

Example Controller Test
src/test/java/com/bytebuilder/checker/controller/WebsiteCheckControllerTest.java:
package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.dto.WebsiteAnalysisResult;
import com.bytebuilder.checker.dto.WebsiteCheckRequest;
import com.bytebuilder.checker.dto.WebsiteCheckResponse;
import com.bytebuilder.checker.service.WebsiteCheckService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(WebsiteCheckController.class)
class WebsiteCheckControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private WebsiteCheckService websiteCheckService;

    @Test
    void testCheckWebsite_Success() throws Exception {
        WebsiteCheckRequest request = new WebsiteCheckRequest();
        request.setUrl("https://example.com");

        WebsiteAnalysisResult result = WebsiteAnalysisResult.builder()
                .url("https://example.com")
                .description("Sample website")
                .isSecure(true)
                .isSafeFromScams(true)
                .isTextSafe(true)
                .isUrlSuspicious(false)
                .safetyMessage("Website appears to be safe.")
                .additionalInfo(Map.of("analysisTimeMs", 1234L))
                .analyzedAt(Instant.now())
                .build();

        when(websiteCheckService.analyzeWebsite("https://example.com")).thenReturn(result);

        mockMvc.perform(post("/api/v1/website/check")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.url").value("https://example.com"))
                .andExpect(jsonPath("$.overallSafe").value(true))
                .andExpect(jsonPath("$.isSafe").value(true));
    }

    @Test
    void testCheckWebsiteAsync_Success() throws Exception {
        WebsiteCheckRequest request = new WebsiteCheckRequest();
        request.setUrl("https://example.com");

        WebsiteAnalysisResult result = WebsiteAnalysisResult.builder()
                .url("https://example.com")
                .description("Sample website")
                .isSecure(true)
                .isSafeFromScams(true)
                .isTextSafe(true)
                .isUrlSuspicious(false)
                .safetyMessage("Website appears to be safe.")
                .additionalInfo(Map.of("analysisTimeMs", 1234L))
                .analyzedAt(Instant.now())
                .build();

        when(websiteCheckService.analyzeWebsiteAsync("https://example.com"))
                .thenReturn(CompletableFuture.completedFuture(result));

        mockMvc.perform(post("/api/v1/website/check-async")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://example.com\"}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.url").value("https://example.com"))
                .andExpect(jsonPath("$.message").value("Analysis started successfully."));
    }

    @Test
    void testGetAsyncResult_Success() throws Exception {
        String trackingId = "track_123e4567-e89b-12d3-a456-426614174000";
        WebsiteAnalysisResult result = WebsiteAnalysisResult.builder()
                .url("https://example.com")
                .description("Sample website")
                .isSecure(true)
                .isSafeFromScams(true)
                .isTextSafe(true)
                .isUrlSuspicious(false)
                .safetyMessage("Website appears to be safe.")
                .additionalInfo(Map.of("analysisTimeMs", 1234L))
                .analyzedAt(Instant.now())
                .build();

        when(websiteCheckService.analyzeWebsiteAsync("https://example.com"))
                .thenReturn(CompletableFuture.completedFuture(result));

        // Simulate async check to store result
        mockMvc.perform(post("/api/v1/website/check-async")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://example.com\"}"));

        mockMvc.perform(get("/api/v1/website/check-async/" + trackingId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.url").value("https://example.com"))
                .andExpect(jsonPath("$.overallSafe").value(true))
                .andExpect(jsonPath("$.isSafe").value(true));
    }

    @Test
    void testGetAsyncResult_InProgress() throws Exception {
        String trackingId = "track_123e4567-e89b-12d3-a456-426614174000";
        CompletableFuture<WebsiteAnalysisResult> future = new CompletableFuture<>();
        when(websiteCheckService.analyzeWebsiteAsync("https://example.com")).thenReturn(future);

        // Simulate async check to store future
        mockMvc.perform(post("/api/v1/website/check-async")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://example.com\"}"));

        mockMvc.perform(get("/api/v1/website/check-async/" + trackingId))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.trackingId").value(trackingId))
                .andExpect(jsonPath("$.message").value("Analysis is still in progress."));
    }

    @Test
    void testGetAsyncResult_NotFound() throws Exception {
        String trackingId = "track_invalid";
        mockMvc.perform(get("/api/v1/website/check-async/" + trackingId))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.trackingId").value(trackingId))
                .andExpect(jsonPath("$.message").value("No analysis found for the given tracking ID."));
    }

    @Test
    void testCheckWebsiteGet_Success() throws Exception {
        WebsiteAnalysisResult result = WebsiteAnalysisResult.builder()
                .url("https://example.com")
                .description("Sample website")
                .isSecure(true)
                .isSafeFromScams(true)
                .isTextSafe(true)
                .isUrlSuspicious(false)
                .safetyMessage("Website appears to be safe.")
                .additionalInfo(Map.of("analysisTimeMs", 1234L))
                .analyzedAt(Instant.now())
                .build();

        when(websiteCheckService.analyzeWebsite("https://example.com")).thenReturn(result);

        mockMvc.perform(get("/api/v1/website/check?url=https://example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.url").value("https://example.com"))
                .andExpect(jsonPath("$.overallSafe").value(true))
                .andExpect(jsonPath("$.isSafe").value(true));
    }

    @Test
    void testHealthCheck() throws Exception {
        mockMvc.perform(get("/api/v1/website/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Website Check Service is running."))
                .andExpect(jsonPath("$.healthy").value(true));
    }
}

Configuration

VirusTotal API:
Configure virustotal.api.key, virustotal.poll.delay, virustotal.max.attempts.


Scraping:
Set content.scraping.timeout (default: 10000ms).


Spring Beans:
Defined in AppConfig.java (OkHttpClient, Gson, NLPContentAnalyzer).


Logging:
Configure in src/main/resources/logback.xml.



Extending the Project
Persistent Async Storage
Replace in-memory ConcurrentHashMap with Redis or a database:

Add Redis dependency:<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-data-redis</artifactId>
<version>3.1.0</version>
</dependency>


Configure Redis in application.properties:spring.redis.host=localhost
spring.redis.port=6379


Update WebsiteCheckController to use RedisTemplate.

Advanced NLP
Enhance NLPContentAnalyzer with:

DeepLearning4J:<dependency>
<groupId>org.deeplearning4j</groupId>
<artifactId>deeplearning4j-nlp</artifactId>
<version>1.0.0-M2.1</version>
</dependency>


OpenAI API for advanced summarization.

Performance

Cache results:@Cacheable("websiteAnalysis")
public WebsiteAnalysisResult analyzeWebsite(String urlString) { ... }


Enable async:@SpringBootApplication
@EnableAsync
public class CheckerApplication { ... }



Security

Add rate limiting with Resilience4j:<dependency>
<groupId>io.github.resilience4j</groupId>
<artifactId>resilience4j-spring-boot3</artifactId>
<version>2.0.2</version>
</dependency>



Troubleshooting

Error: client not initialized:
Verify AppConfig.java defines all beans.
Ensure @SpringBootApplication scans com.bytebuilder.checker.


VirusTotal API Issues:
Check API key and rate limits.
Adjust virustotal.max.attempts or poll.delay.


Validation Errors:
Ensure WebsiteCheckRequest has a valid URL.


Async Result Issues:
Verify trackingId exists and analysis is complete.
Check logs for errors during async processing.



Contributing

Fork the repository.
Create a feature branch (git checkout -b feature/new-feature).
Commit changes (git commit -m "Add new feature").
Push to the branch (git push origin feature/new-feature).
Open a pull request.

License
MIT License. See LICENSE.
Contact
Contact your-email@example.com.