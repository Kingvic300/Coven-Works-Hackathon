package com.bytebuilder.checker.dto.response;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SendVerificationEmailResponse {
    private String message;
    private String otp;
}
