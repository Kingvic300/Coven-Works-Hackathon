package com.bytebuilder.checker.dto.response;

import com.bytebuilder.checker.data.model.User;
import lombok.Data;

@Data
public class CreatedUserResponse {
    private User user;
    private String message;
    private String jwtToken;

}
