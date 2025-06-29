package com.bytebuilder.checker.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;


public class WebsiteCheckRequest {
    private String url;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
