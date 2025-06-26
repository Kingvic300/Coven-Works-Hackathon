package com.bytebuilder.checker.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
public class WebsiteCheckResponse {
    private  String url;
    private  String description;
    private  boolean isSecure;
    private  boolean isSafeFromScams;
    private  boolean isTextSafe;
    private  String safetyMessage;

    // Constructors in case the lombok doesnt work for you --- Akerele

    public WebsiteCheckResponse(String url, String description, boolean isSecure,
                                 boolean isSafeFromScams, boolean isTextSafe, String safetyMessage) {
        this.url = url;
        this.description = description;
        this.isSecure = isSecure;
        this.isSafeFromScams = isSafeFromScams;
        this.isTextSafe = isTextSafe;
        this.safetyMessage = safetyMessage;
    }
    public String getUrl() {
        return url;
    }

    public String getDescription() {
        return description;
    }

    public boolean isSecure() {
        return isSecure;
    }

    public boolean isSafeFromScams() {
        return isSafeFromScams;
    }

    public boolean isTextSafe() {
        return isTextSafe;
    }

    public String getSafetyMessage() {
        return safetyMessage;
    }
}