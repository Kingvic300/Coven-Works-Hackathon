package com.bytebuilder.checker.service;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import lombok.RequiredArgsConstructor;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class WebsiteCheckService {
    private final OkHttpClient client;
    private final Gson gson;

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    public boolean isSecure(String urlString) {
        try {
            URI uri = new URI(urlString);
            if (!uri.getScheme().equalsIgnoreCase("https")) {
                return false;
            }

            HttpsURLConnection connection = (HttpsURLConnection) uri.toURL().openConnection();
            connection.connect();

            Certificate[] certs = connection.getServerCertificates();
            if (certs == null || certs.length == 0) {
                return false;
            }

            for (Certificate cert : certs) {
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    x509Cert.checkValidity();
                }
            }
            return true;

        } catch (Exception e) {
            return false;
        }
    }

    public boolean isSafeFromScams(String urlString) {
        try {

            String encodedUrl = Base64.getUrlEncoder().encodeToString(urlString.getBytes());
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
                    return false;
                }

                String scanResponseBody = scanResponse.body().string();
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
                    Thread.sleep(3000);
                    try (Response analysisResponse = client.newCall(analysisRequest).execute()) {
                        if (!analysisResponse.isSuccessful()) {
                            return false;
                        }
                        assert analysisResponse.body() != null;
                        String analysisResponseBody = analysisResponse.body().string();
                        analysisJson = gson.fromJson(analysisResponseBody, JsonObject.class);
                        status = analysisJson.getAsJsonObject("data").getAsJsonObject("attributes").get("status").getAsString();
                        attempt++;
                    }
                } while (status.equals("queued") && attempt < maxAttempts);

                if (!status.equals("completed")) {
                    return false;
                }

                JsonObject stats = analysisJson.getAsJsonObject("data").getAsJsonObject("attributes").getAsJsonObject("stats");
                int malicious = stats.get("malicious").getAsInt();
                int suspicious = stats.get("suspicious").getAsInt();

                return malicious == 0 && suspicious == 0;

            }
        } catch (Exception e) {
            return false;
        }
    }
}