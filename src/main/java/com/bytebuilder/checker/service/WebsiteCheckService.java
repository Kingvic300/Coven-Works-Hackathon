package com.bytebuilder.checker.service;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import okhttp3.*;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class WebsiteCheckService {
    private static final Logger LOGGER = LoggerFactory.getLogger(WebsiteCheckService.class);

    private  OkHttpClient client;
    private  Gson gson;

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    @Value("${virustotal.poll.delay:3000}")
    private long pollDelayMillis;

    @Autowired
    public WebsiteCheckService(OkHttpClient client, Gson gson) {
        this.client = client;
        this.gson = gson;
    }


    // Common scam keywords for text analysis
    private static final Set<String> SCAM_KEYWORDS = new HashSet<>(Arrays.asList(
            "get rich quick", "urgent action required", "free money", "win a prize",
            "verify your account now", "limited time offer", "click here to claim"
    ));

    public static class WebsiteAnalysisResult {
        private String url;
        private String description;
        private boolean isSecure;
        private boolean isSafeFromScams;
        private boolean isTextSafe;
        private String safetyMessage;



        public WebsiteAnalysisResult(String url, String description, boolean isSecure,
                                     boolean isSafeFromScams, boolean isTextSafe, String safetyMessage) {
            this.url = url;
            this.description = description;
            this.isSecure = isSecure;
            this.isSafeFromScams = isSafeFromScams;
            this.isTextSafe = isTextSafe;
            this.safetyMessage = safetyMessage;
        }
        public String getDescription() {
            return this.description;
        }

        public String getSafetyMessage() {
            return safetyMessage;
        }

        public boolean isSafeFromScams() {
            return isSafeFromScams;
        }

        public boolean isSecure() {
            return isSecure;
        }

        public boolean isTextSafe() {
            return isTextSafe;
        }

        public String getUrl() {
            return this.url;
        }
    }


    public WebsiteAnalysisResult analyzeWebsite(String urlString) {
        try {
            // Validate and normalize URL
            URI uri = new URI(urlString);
            String normalizedUrl = uri.toString();

            // Check HTTPS security
            boolean isSecure = isSecure(normalizedUrl);
            // Check VirusTotal for scams
            boolean isSafeFromScams = isSafeFromScams(normalizedUrl);
            // Scrape website and analyze content
            String[] contentAnalysis = analyzeWebsiteContent(normalizedUrl);
            String description = contentAnalysis[0];
            boolean isTextSafe = Boolean.parseBoolean(contentAnalysis[1]);

            // Determine overall safety message
            String safetyMessage = determineSafetyMessage(isSecure, isSafeFromScams, isTextSafe);

            return new WebsiteAnalysisResult(normalizedUrl, description, isSecure,
                    isSafeFromScams, isTextSafe, safetyMessage);

        } catch (Exception e) {
            LOGGER.error("Failed to analyze website: {}", urlString, e);
            return new WebsiteAnalysisResult(urlString, "Unable to generate description",
                    false, false, false, "Analysis failed due to error");
        }
    }

    private String[] analyzeWebsiteContent(String urlString) {
        try {
            // Scrape website content
            Document doc = Jsoup.connect(urlString).timeout(10000).get();

            // Extract relevant text for description
            String title = doc.title();
            String metaDescription = doc.select("meta[name=description]").attr("content");
            String heading = doc.select("h1").text();
            String bodyText = doc.select("p").stream()
                    .map(element -> element.text().trim())
                    .filter(text -> !text.isEmpty())
                    .limit(3)
                    .collect(Collectors.joining(" "));

            // Generate description (simple concatenation with length limit)
            String rawDescription = (title + " " + metaDescription + " " + heading + " " + bodyText).trim();
            String description = rawDescription.length() > 200
                    ? rawDescription.substring(0, 197) + "..."
                    : rawDescription;

            if (description.isEmpty()) {
                description = "No description available";
            }

            // Check for scam keywords
            boolean isTextSafe = isTextSafe(rawDescription.toLowerCase());

            // Optional: Integrate advanced NLP (e.g., Hugging Face Transformers)
            // Example: Use a summarization model to generate a more concise description
            // String summarizedDescription = summarizeWithNLP(rawDescription);

            LOGGER.info("Generated description for URL: {}, description: {}", urlString, description);
            return new String[]{description, String.valueOf(isTextSafe)};

        } catch (IOException e) {
            LOGGER.error("Failed to scrape website content: {}", urlString, e);
            return new String[]{"Unable to scrape content", "false"};
        }
    }

    private boolean isTextSafe(String text) {
        // Simple keyword-based scam detection
        for (String keyword : SCAM_KEYWORDS) {
            if (text.contains(keyword.toLowerCase())) {
                LOGGER.warn("Detected potential scam keyword '{}' in website content", keyword);
                return false;
            }
        }
        // Optional: Integrate sentiment analysis or advanced NLP for better scam detection
        // Example: Use a classifier to detect phishing intent
        return true;
    }

    private String determineSafetyMessage(boolean isSecure, boolean isSafeFromScams, boolean isTextSafe) {
        if (isSecure && isSafeFromScams && isTextSafe) {
            return "Website is likely safe";
        } else if (!isSecure) {
            return "Website is potentially unsafe due to lack of HTTPS";
        } else if (!isSafeFromScams) {
            return "Website is potentially unsafe based on VirusTotal scan";
        } else {
            return "Website is potentially unsafe due to suspicious content";
        }
    }

    public boolean isSecure(String urlString) {
        HttpsURLConnection connection = null;
        try {
            URI uri = new URI(urlString);
            if (!uri.getScheme().equalsIgnoreCase("https")) {
                LOGGER.warn("Non-HTTPS URL provided: {}", urlString);
                return false;
            }

            URL url = uri.toURL();
            connection = (HttpsURLConnection) url.openConnection();

            // Set up SSL context for enhanced certificate validation
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
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, null);
            connection.setSSLSocketFactory(sslContext.getSocketFactory());

            connection.connect();
            Certificate[] certs = connection.getServerCertificates();
            if (certs == null || certs.length == 0) {
                LOGGER.warn("No certificates found for URL: {}", urlString);
                return false;
            }

            LOGGER.info("Successfully validated certificates for URL: {}", urlString);
            return true;

        } catch (URISyntaxException e) {
            LOGGER.error("Invalid URL syntax: {}", urlString, e);
            return false;
        } catch (IOException e) {
            LOGGER.error("IO error while checking URL: {}", urlString, e);
            return false;
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("SSL context initialization failed for URL: {}", urlString, e);
            return false;
        } catch (KeyManagementException e) {
            LOGGER.error("Key management error for URL: {}", urlString, e);
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public boolean isSafeFromScams(String urlString) {
        try {
            FormBody formBody = new FormBody.Builder()
                    .add("url", urlString)
                    .build();

            Request scanRequest = new Request.Builder()
                    .url("https://www.virustotal.com/api/v3/urls")
                    .post(formBody)
                    .addHeader("x-apikey", virusTotalApiKey)
                    .build();

            try (Response scanResponse = client.newCall(scanRequest).execute()) {
                if (!scanResponse.isSuccessful()) {
                    LOGGER.warn("VirusTotal scan request failed for URL: {}, status: {}", urlString, scanResponse.code());
                    return false;
                }

                String scanResponseBody = Objects.requireNonNull(scanResponse.body(), "Scan response body is null").string();
                JsonObject scanJson = gson.fromJson(scanResponseBody, JsonObject.class);
                String scanId = scanJson.getAsJsonObject("data").get("id").getAsString();

                Request analysisRequest = new Request.Builder()
                        .url("https://www.virustotal.com/api/v3/analyses/" + scanId)
                        .get()
                        .addHeader("x-apikey", virusTotalApiKey)
                        .build();

                JsonObject analysisJson;
                String status;
                int maxAttempts = 5;
                int attempt = 0;

                do {
                    Thread.sleep(pollDelayMillis);
                    try (Response analysisResponse = client.newCall(analysisRequest).execute()) {
                        if (!analysisResponse.isSuccessful()) {
                            LOGGER.warn("VirusTotal analysis request failed for URL: {}, status: {}", urlString, analysisResponse.code());
                            return false;
                        }
                        String analysisResponseBody = Objects.requireNonNull(analysisResponse.body(), "Analysis response body is null").string();
                        analysisJson = gson.fromJson(analysisResponseBody, JsonObject.class);
                        status = analysisJson.getAsJsonObject("data").getAsJsonObject("attributes").get("status").getAsString();
                        attempt++;
                    }
                } while (status.equals("queued") && attempt < maxAttempts);

                if (!status.equals("completed")) {
                    LOGGER.warn("VirusTotal analysis not completed for URL: {}", urlString);
                    return false;
                }

                JsonObject stats = analysisJson.getAsJsonObject("data").getAsJsonObject("attributes").getAsJsonObject("stats");
                int malicious = stats.get("malicious").getAsInt();
                int suspicious = stats.get("suspicious").getAsInt();

                boolean isSafe = malicious == 0 && suspicious == 0;
                LOGGER.info("VirusTotal scan result for URL: {}, malicious: {}, suspicious: {}, isSafe: {}",
                        urlString, malicious, suspicious, isSafe);
                return isSafe;

            }
        } catch (IOException e) {
            LOGGER.error("IO error during VirusTotal API call for URL: {}", urlString, e);
            return false;
        } catch (InterruptedException e) {
            LOGGER.error("Interrupted while polling VirusTotal API for URL: {}", urlString, e);
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            LOGGER.error("Unexpected error while checking URL safety: {}", urlString, e);
            return false;
        }
    }
}