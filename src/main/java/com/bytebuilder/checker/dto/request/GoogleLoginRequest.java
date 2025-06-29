package com.bytebuilder.checker.dto.request;

import lombok.Data;

@Data
public class GoogleLoginRequest {
    private String token;
    private String role;
}
