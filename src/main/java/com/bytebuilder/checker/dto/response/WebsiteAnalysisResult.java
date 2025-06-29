package com.bytebuilder.checker.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class WebsiteAnalysisResult {
    private final String url;
    private final String description;
    private final boolean isSecure;
    private final boolean isSafeFromScams;
    private final boolean isTextSafe;
    private final String safetyMessage;
}
