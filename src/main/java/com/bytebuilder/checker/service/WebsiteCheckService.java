package com.bytebuilder.checker.service;

import com.bytebuilder.checker.dto.response.WebsiteAnalysisResult;
import com.bytebuilder.checker.exception.NonHTTPSUrlException;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import okhttp3.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URL;

@Service
@RequiredArgsConstructor
public class WebsiteCheckService {

    private static final Logger logger = LoggerFactory.getLogger(WebsiteCheckService.class);

    private final OkHttpClient client = new OkHttpClient();
    private final Gson gson = new Gson();

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    public WebsiteAnalysisResult analyzeWebsite(String url) {
        try {
            if (!url.startsWith("https://")) {
                throw new NonHTTPSUrlException("Only HTTPS URLs are allowed.");
            }

            boolean isSecure = checkSSL(url);
            boolean isSuspicious = checkUrlSuspiciousness(url);
            String title = fetchWebsiteTitle(url);
            boolean isSafe = !isSuspicious;

            String safetyMessage = generateSafetyMessage(isSecure, isSafe);

            return new WebsiteAnalysisResult(
                    url,
                    title,
                    isSecure,
                    isSafe,
                    true, // Assuming text is safe if it loads properly. You can implement your own text analysis.
                    safetyMessage
            );

        } catch (NonHTTPSUrlException e) {
            return new WebsiteAnalysisResult(
                    url,
                    "N/A",
                    false,
                    false,
                    false,
                    "Only HTTPS URLs are allowed for analysis."
            );
        } catch (Exception e) {
            logger.error("Error analyzing website: {}", e.getMessage());
            return new WebsiteAnalysisResult(
                    url,
                    "N/A",
                    false,
                    false,
                    false,
                    "An internal error occurred during analysis."
            );
        }
    }

    private boolean checkSSL(String urlString) {
        try {
            URL url = new URL(urlString);
            return "https".equalsIgnoreCase(url.getProtocol());
        } catch (Exception e) {
            logger.error("Error checking SSL: {}", e.getMessage());
            return false;
        }
    }

    private boolean checkUrlSuspiciousness(String urlString) {
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

        Thread.sleep(5000); // wait for scan

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) return true;

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

    private String fetchWebsiteTitle(String url) {
        try {
            Document doc = Jsoup.connect(url).get();
            return doc.title();
        } catch (IOException e) {
            logger.error("Error fetching website content: {}", e.getMessage());
            return "Unable to retrieve title";
        }
    }

    private String generateSafetyMessage(boolean isSecure, boolean isSafeFromScams) {
        if (!isSecure) return "This website is not using HTTPS and may be insecure.";
        if (!isSafeFromScams) return "This website may be malicious or suspicious.";
        return "This website appears to be safe and secure.";
    }
}
