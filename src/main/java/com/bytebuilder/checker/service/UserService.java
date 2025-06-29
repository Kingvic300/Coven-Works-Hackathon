package com.bytebuilder.checker.service;

import com.bytebuilder.checker.dto.request.*;
import com.bytebuilder.checker.dto.response.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface UserService {
    OTPResponse sendVerificationOTP(CreateUserRequest request);
    CreatedUserResponse register(RegisterUserRequest request);
    UploadResponse uploadFile(MultipartFile file) throws IOException;
    LoginResponse login(LoginRequest loginResponse);
    UpdateUserProfileResponse updateProfile(UpdateUserProfileRequest updateUserProfileRequest);
    ResetPasswordResponse resetPassword(ChangePasswordRequest changePasswordRequest);
    ResetPasswordResponse sendResetOtp(ResetPasswordRequest resetPasswordRequest);
    LoginResponse handleGoogleLogin(String email, String name, String role);

    FoundResponse findUserById(String id);
}

