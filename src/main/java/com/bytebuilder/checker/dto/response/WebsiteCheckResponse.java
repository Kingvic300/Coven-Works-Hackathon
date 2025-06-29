package com.bytebuilder.checker.dto.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@RequiredArgsConstructor
public class WebsiteCheckResponse {
    private  String url;
    private  String description;
    private  boolean isSecure;
    private  boolean isSafeFromScams;
    private  boolean isTextSafe;
    private  String safetyMessage;

}