package com.bytebuilder.checker.mapper;

import com.bytebuilder.checker.data.model.User;
import com.bytebuilder.checker.dto.request.CreateUserRequest;
import com.bytebuilder.checker.dto.request.UpdateUserProfileRequest;
import com.bytebuilder.checker.dto.response.*;
import com.bytebuilder.checker.util.EmailVerification;

import java.util.UUID;

public class UserMapper {
    public static User mapToUser(CreateUserRequest createUserRequest) {
        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setPassword(createUserRequest.getPassword());
        user.setEmail(EmailVerification.emailVerification(createUserRequest.getEmail()));
        user.setRole(createUserRequest.getRole());
        return user;
    }
    public static void mapToUpdateProfile(UpdateUserProfileRequest updateUserProfileRequest, User user) {
        user.setFullName(updateUserProfileRequest.getFullName());
        user.setEmail(updateUserProfileRequest.getEmail());
        user.setPhoneNumber(updateUserProfileRequest.getPhoneNumber());
        user.setRole(updateUserProfileRequest.getRoles());
        user.setLocation(updateUserProfileRequest.getLocation());
        user.setProfilePicturePath(updateUserProfileRequest.getProfilePicturePath());
        user.setActive(user.isActive());
    }
    public static UpdateUserProfileResponse mapToUpdateUserProfileResponse(String token, String message) {
        UpdateUserProfileResponse updateUserProfileResponse = new UpdateUserProfileResponse();
        updateUserProfileResponse.setMessage(message);
        updateUserProfileResponse.setToken(token);
        return updateUserProfileResponse;
    }
    public static CreatedUserResponse mapToCreatedUserResponse(String jwtToken, User user, String message) {
        CreatedUserResponse createdUserResponse = new CreatedUserResponse();
        createdUserResponse.setUser(user);
        createdUserResponse.setMessage(message);
        createdUserResponse.setJwtToken(jwtToken);
        return createdUserResponse;
    }
    public static LoginResponse mapToLoginResponse(String jwtToken, String message, User user) {
        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setToken(jwtToken);
        loginResponse.setMessage(message);
        loginResponse.setUser(user);
        System.out.println(user.getRole());
        System.out.println(user.isGoogleUser());
        return loginResponse;
    }
    public static ResetPasswordResponse mapToResetPasswordResponse(String message, String otp, String email) {
        ResetPasswordResponse resetPasswordResponse = new ResetPasswordResponse();
        resetPasswordResponse.setMessage(message);
        resetPasswordResponse.setOtp(otp);
        resetPasswordResponse.setEmail(email);
        return resetPasswordResponse;
    }
    public static UploadResponse mapToUploadResponse(String message, String cloudinaryUrl){
        UploadResponse uploadResponse = new UploadResponse();
        uploadResponse.setMessage(message);
        uploadResponse.setCloudinaryUrl(cloudinaryUrl);
        return uploadResponse;
    }

    public static OTPResponse mapToOtpSentResponse(String message, String email) {
        return OTPMapper.mapToOTPResponse(message, email);
    }
    public static FoundResponse mapToFoundResponse(String message, String id){
        FoundResponse foundResponse = new FoundResponse();
        foundResponse.setMessage(message);
        foundResponse.setId(id);
        return foundResponse;
    }
}
