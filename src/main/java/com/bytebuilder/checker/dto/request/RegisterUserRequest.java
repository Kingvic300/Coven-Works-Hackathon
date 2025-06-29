package com.bytebuilder.checker.dto.request;

import com.bytebuilder.checker.data.enums.Role;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class RegisterUserRequest {
    private String email;
    private String otp;
    private Role role;
}
