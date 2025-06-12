package com.bytebuilder.checker.service;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class WebsiteCheckService {
    private static final Logger LOGGER = LoggerFactory.getLogger(WebsiteCheckService.class);

    private final OkHttpClient client;
    private final Gson gson;

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    @Value("${virustotal.poll.delay:3000}")
    private long pollDelayMillis;

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


            SSLContext sslContext = SSLContext.getInstance("TLS");
            HttpsURLConnection finalConnection = connection;
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {

                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    for (X509Certificate cert : chain) {
                        cert.checkValidity();
                    }
                    if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(uri.getHost(), finalConnection.getSSLSession().get())) {
                        throw new CertificateException("Hostname verification failed for " + uri.getHost());
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

            try (Response scanResponse = client.newCall(scanRequest).execute())
            {
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
                    LOGGER.warn("Virus Applies to all VirusTotal analysis not completed for URL: {}", urlString);
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