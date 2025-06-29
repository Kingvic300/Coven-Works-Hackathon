package com.bytebuilder.checker.dto.response;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ResetPasswordResponse {
    private String message;
    private String otp;
    private String email;
}
