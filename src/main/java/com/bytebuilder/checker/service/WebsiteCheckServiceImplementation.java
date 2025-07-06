package com.bytebuilder.checker.service;

import com.bytebuilder.checker.dto.response.WebsiteAnalysisResult;
import com.bytebuilder.checker.exception.NonHTTPSUrlException;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import okhttp3.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Service
@RequiredArgsConstructor
public class WebsiteCheckServiceImplementation implements WebsiteCheckService {

    private static final Logger logger = LoggerFactory.getLogger(WebsiteCheckServiceImplementation.class);

    private final OkHttpClient client = new OkHttpClient();
    private final Gson gson = new Gson();

    private final AiService aiService;
    private List<String> scamKeywords;

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    @Override
    public WebsiteAnalysisResult analyzeWebsite(String url) {
        try {
            if (!url.startsWith("https://")) {
                throw new NonHTTPSUrlException("Only HTTPS URLs are allowed.");
            }

            boolean usesHttps = checkSSL(url);
            boolean scamOrMalwareDetected = checkIfUrlIsSuspicious(url);
            boolean scamKeywordsDetected = containsScamKeywords(url);
            boolean inappropriateContentDetected = false; // Extend logic if needed

            boolean isSafe = !scamOrMalwareDetected && !scamKeywordsDetected && !inappropriateContentDetected;

            String title = fetchWebsiteTitle(url);

            String safetyMessage = generateSafetyMessageWithAI(
                    url,
                    usesHttps,
                    scamOrMalwareDetected,
                    scamKeywordsDetected,
                    inappropriateContentDetected
            );

            return new WebsiteAnalysisResult(
                    url,
                    title,
                    usesHttps,
                    isSafe,
                    !scamKeywordsDetected,
                    safetyMessage
            );

        } catch (NonHTTPSUrlException e) {
            throw new NonHTTPSUrlException(url + " Only HTTPS URLs are allowed for analysis.");
        } catch (Exception e) {
            logger.error("Error analyzing website: {}", e.getMessage());
            throw new RuntimeException("An error occurred while analyzing the website: " + e.getMessage(), e);
        }
    }

    private boolean checkSSL(String urlString) {
        try {
            URL url = new URL(urlString);
            boolean isHttps = "https".equalsIgnoreCase(url.getProtocol());
            int port = url.getPort();
            return isHttps && (port == -1 || port == 443);
        } catch (Exception e) {
            logger.error("Error checking SSL: {}", e.getMessage());
            return false;
        }
    }

    private boolean checkIfUrlIsSuspicious(String urlString) {
        try {
            HttpUrl apiUrl = HttpUrl.parse("https://www.virustotal.com/api/v3/urls");
            if (apiUrl == null) return true;

            RequestBody body = new FormBody.Builder()
                    .add("url", urlString)
                    .build();

            Request request = new Request.Builder()
                    .url(apiUrl)
                    .post(body)
                    .addHeader("x-apikey", virusTotalApiKey)
                    .build();

            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    logger.warn("VirusTotal scan request failed: {}", response);
                    return true;
                }

                assert response.body() != null;
                String responseBody = response.body().string();
                JsonObject json = gson.fromJson(responseBody, JsonObject.class);
                String scanId = json.getAsJsonObject("data").get("id").getAsString();

                return fetchVirusTotalAnalysis(scanId);
            }
        } catch (Exception e) {
            logger.error("Error checking URL suspiciousness: {}", e.getMessage());
            return true;
        }
    }

    private boolean fetchVirusTotalAnalysis(String scanId) throws IOException, InterruptedException {
        HttpUrl url = HttpUrl.parse("https://www.virustotal.com/api/v3/analyses/" + scanId);
        if (url == null) return true;

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("x-apikey", virusTotalApiKey)
                .build();

        Thread.sleep(5000);

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) return true;

            assert response.body() != null;
            String responseBody = response.body().string();
            JsonObject json = gson.fromJson(responseBody, JsonObject.class);
            JsonObject stats = json.getAsJsonObject("data")
                    .getAsJsonObject("attributes")
                    .getAsJsonObject("stats");

            int malicious = stats.get("malicious").getAsInt();
            int suspicious = stats.get("suspicious").getAsInt();

            return (malicious + suspicious) > 0;
        }
    }

    private boolean containsScamKeywords(String url) {
        try {
            Document doc = Jsoup.connect(url).get();
            String text = doc.text().toLowerCase();

            for (String keyword : scamKeywords) {
                if (text.contains(keyword)) {
                    logger.warn("Scam keyword found in content: {}", keyword);
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            logger.error("Error analyzing page text for scam keywords: {}", e.getMessage());
            return true;
        }
    }

    private String fetchWebsiteTitle(String url) {
        try {
            Document doc = Jsoup.connect(url).get();
            return doc.title();
        } catch (IOException e) {
            logger.error("Error fetching website content: {}", e.getMessage());
            return "Unable to retrieve title";
        }
    }

    private String generateSafetyMessageWithAI(String url, boolean usesHttps, boolean scamOrMalwareDetected, boolean scamKeywordsDetected, boolean inappropriateContentDetected) {
        String template = loadPromptTemplate();

        if (template.isBlank()) {
            logger.warn("Prompt template not loaded, falling back.");
            return generateFallbackMessage(usesHttps, scamOrMalwareDetected);
        }

        // ✅ Fixed: 5 args for 5 placeholders
        String prompt = String.format(template, url, usesHttps, scamOrMalwareDetected, scamKeywordsDetected, inappropriateContentDetected);

        try {
            return aiService.chat(prompt);
        } catch (Exception e) {
            logger.warn("AI service failed, using fallback message.");
            return generateFallbackMessage(usesHttps, scamOrMalwareDetected);
        }
    }

    private String generateFallbackMessage(boolean isSecure, boolean isSuspicious) {
        if (!isSecure) return "This website is not using HTTPS and may be insecure.";
        if (isSuspicious) return "This website may be malicious or suspicious.";
        return "This website appears to be safe and secure.";
    }

    private String loadPromptTemplate() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("prompts/website_safety_prompt.txt")) {
            if (is == null) {
                throw new IOException("Prompt file not found: prompts/website_safety_prompt.txt");
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            logger.error("Failed to load AI prompt template: {}", e.getMessage());
            return "";
        }
    }

    @PostConstruct
    private void loadScamKeywords() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("scan_keywords.txt")) {
            if (is == null) throw new IOException("scan_keywords.txt not found");

            this.scamKeywords = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))
                    .lines()
                    .filter(line -> !line.trim().isEmpty())
                    .map(String::toLowerCase)
                    .toList();

            logger.info("Loaded {} scam keywords.", scamKeywords.size());
        } catch (IOException e) {
            logger.error("Failed to load scam keywords: {}", e.getMessage());
            this.scamKeywords = List.of();
        }
    }
}
