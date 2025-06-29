package com.bytebuilder.checker.dto.request;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SendVerificationEmailRequest {
    private String email;
}
