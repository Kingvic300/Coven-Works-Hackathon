package com.bytebuilder.checker.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
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
public  class WebsiteAnalysisResult { // This is the static nested class
    private String url;
    private String description;
    private boolean isSecure;
    private boolean isSafeFromScams;
    private boolean isTextSafe;
    private boolean isUrlSuspicious;
    private String safetyMessage;
    private Map<String, Object> additionalInfo;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
    private Instant analyzedAt;
}
