package com.bytebuilder.checker.dto.request;

import com.bytebuilder.checker.data.enums.Role;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateUserRequest {
    private String password;
    private String email;
    private Role role;
}
