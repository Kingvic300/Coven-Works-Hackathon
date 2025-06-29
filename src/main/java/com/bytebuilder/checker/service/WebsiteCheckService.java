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

import javax.annotation.PostConstruct;
import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class WebsiteCheckService {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebsiteCheckService.class);

    private final OkHttpClient client;
    private final Gson gson;

    private Set<String> scamKeywords;

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    @Value("${virustotal.poll.delay}")
    private long pollDelayMillis;

    @PostConstruct
    private void loadKeywords() {
        this.scamKeywords = loadScamKeywordsFromFile();
    }

    public WebsiteAnalysisResult analyzeWebsite(String urlString) {
        try {
            URI uri = new URI(urlString);
            String normalizedUrl = uri.toString();

            boolean isSecure = isSecure(normalizedUrl);
            boolean isSafeFromScams = isSafeFromScams(normalizedUrl);
            String[] contentAnalysis = analyzeWebsiteContent(normalizedUrl);
            String description = contentAnalysis[0];
            boolean isTextSafe = Boolean.parseBoolean(contentAnalysis[1]);

            String safetyMessage = determineSafetyMessage(isSecure, isSafeFromScams, isTextSafe);

            return new WebsiteAnalysisResult(normalizedUrl, description, isSecure, isSafeFromScams, isTextSafe, safetyMessage);

        } catch (Exception e) {
            LOGGER.error("Failed to analyze website: {}", urlString, e);
            return new WebsiteAnalysisResult(urlString, "Unable to generate description", false, false, false, "Analysis failed due to error");
        }
    }

    public boolean isSecure(String urlString) {
        HttpsURLConnection connection = null;
        try {
            URI uri = new URI(urlString);
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                LOGGER.warn("Non-HTTPS URL provided: {}", urlString);
                throw new NonHTTPSUrlException("URL is not secure: " + urlString);
            }

            URL url = uri.toURL();
            connection = (HttpsURLConnection) url.openConnection();

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) { }
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    if (chain == null || chain.length == 0) {
                        throw new CertificateException("No server certificates found");
                    }
                    for (X509Certificate cert : chain) {
                        cert.checkValidity();
                    }
                }
                @Override
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);

            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.connect();

            Certificate[] certs = connection.getServerCertificates();
            return certs != null && certs.length > 0;

        } catch (Exception e) {
            LOGGER.error("Security check failed for URL: {}", urlString, e);
            return false;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    public boolean isSafeFromScams(String urlString) {
        try {
            FormBody formBody = new FormBody.Builder().add("url", urlString).build();

            Request scanRequest = new Request.Builder()
                    .url("https://www.virustotal.com/api/v3/urls")
                    .post(formBody)
                    .addHeader("x-apikey", virusTotalApiKey)
                    .build();

            try (Response scanResponse = client.newCall(scanRequest).execute()) {
                if (!scanResponse.isSuccessful()) {
                    LOGGER.warn("VirusTotal scan failed for {}, status: {}", urlString, scanResponse.code());
                    return false;
                }

                String scanResponseBody = Objects.requireNonNull(scanResponse.body()).string();
                JsonObject scanJson = gson.fromJson(scanResponseBody, JsonObject.class);
                String scanId = scanJson.getAsJsonObject("data").get("id").getAsString();

                Request analysisRequest = new Request.Builder()
                        .url("https://www.virustotal.com/api/v3/analyses/" + scanId)
                        .get()
                        .addHeader("x-apikey", virusTotalApiKey)
                        .build();

                JsonObject analysisJson;
                String status;
                int attempt = 0;
                int maxAttempts = 5;

                do {
                    Thread.sleep(pollDelayMillis);
                    try (Response analysisResponse = client.newCall(analysisRequest).execute()) {
                        if (!analysisResponse.isSuccessful()) {
                            LOGGER.warn("VirusTotal analysis failed for {}, status: {}", urlString, analysisResponse.code());
                            return false;
                        }
                        String analysisResponseBody = Objects.requireNonNull(analysisResponse.body()).string();
                        analysisJson = gson.fromJson(analysisResponseBody, JsonObject.class);
                        status = analysisJson.getAsJsonObject("data").getAsJsonObject("attributes").get("status").getAsString();
                        attempt++;
                    }
                } while ("queued".equals(status) && attempt < maxAttempts);

                if (!"completed".equals(status)) {
                    LOGGER.warn("VirusTotal analysis not completed for URL: {}", urlString);
                    return false;
                }

                JsonObject stats = analysisJson.getAsJsonObject("data")
                        .getAsJsonObject("attributes").getAsJsonObject("stats");

                int malicious = stats.get("malicious").getAsInt();
                int suspicious = stats.get("suspicious").getAsInt();

                boolean isSafe = malicious == 0 && suspicious == 0;
                LOGGER.info("VirusTotal result for {}: malicious={}, suspicious={}, isSafe={}", urlString, malicious, suspicious, isSafe);
                return isSafe;
            }
        } catch (Exception e) {
            LOGGER.error("VirusTotal check error for URL: {}", urlString, e);
            return false;
        }
    }

    private Set<String> loadScamKeywordsFromFile() {
        Set<String> keywords = new HashSet<>();
        try (InputStream inputStream = Objects
                .requireNonNull(getClass()
                        .getClassLoader()
                        .getResourceAsStream("scam-keywords.txt"));
             InputStreamReader streamReader = new InputStreamReader(inputStream);
             BufferedReader reader = new BufferedReader(streamReader)) {

            String line;
            while ((line = reader.readLine()) != null) {
                String keyword = line.trim().toLowerCase();
                if (!keyword.isEmpty()) {
                    keywords.add(keyword);
                }
            }
        } catch (Exception e) {
            LOGGER.error("Failed to load scam keywords from file", e);
        }
        return keywords;
    }
    private String determineSafetyMessage(boolean isSecure, boolean isSafeFromScams, boolean isTextSafe) {
        if (!isSecure) {
            return "Website is potentially unsafe due to lack of HTTPS";
        }
        if (!isSafeFromScams) {
            return "Website is potentially unsafe based on VirusTotal scan";
        }
        if (!isTextSafe) {
            return "Website is potentially unsafe due to suspicious content";
        }
        return "Website is likely safe";
    }

    private boolean isTextSafe(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        for (String keyword : scamKeywords) {
            if (text.contains(keyword)) {
                LOGGER.warn("Suspicious content found in text: {}", keyword);
                return false;
            }
        }
        return true;
    }
    private String[] analyzeWebsiteContent(String urlString) {
        try {
            Document doc = Jsoup.connect(urlString).timeout(10000).get();

            String title = doc.title();
            String metaDescription = doc.select("meta[name=description]").attr("content");
            String heading = doc.select("h1").text();
            String bodyText = doc.select("p").stream()
                    .map(element -> element.text().trim())
                    .filter(text -> !text.isEmpty())
                    .limit(3)
                    .collect(Collectors.joining(" "));

            String rawDescription = (title + " " + metaDescription + " " + heading + " " + bodyText).trim();
            String description = rawDescription.length() > 200
                    ? rawDescription.substring(0, 197) + "..."
                    : rawDescription;

            if (description.isEmpty()) {
                description = "No description available";
            }

            boolean isTextSafe = isTextSafe(rawDescription.toLowerCase());

            LOGGER.info("Generated description for URL: {}, description: {}", urlString, description);
            return new String[]{description, String.valueOf(isTextSafe)};
        } catch (IOException e) {
            LOGGER.error("Failed to scrape website content: {}", urlString, e);
            return new String[]{"Unable to scrape content", "false"};
        }
    }

}
