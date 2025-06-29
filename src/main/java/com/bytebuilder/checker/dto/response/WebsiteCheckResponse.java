package com.bytebuilder.checker.dto;

public class WebsiteCheckResponse {
    private String url;
    private boolean isSecure;
    private boolean isSafe;
    private String message;

    public WebsiteCheckResponse(String url, boolean isSecure, boolean isSafe, String message) {
        this.url = url;
        this.isSecure = isSecure;
        this.isSafe = isSafe;
        this.message = message;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean isSecure() {
        return isSecure;
    }

    public void setSecure(boolean secure) {
        isSecure = secure;
    }

    public boolean isSafe() {
        return isSafe;
    }

    public void setSafe(boolean safe) {
        isSafe = safe;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
