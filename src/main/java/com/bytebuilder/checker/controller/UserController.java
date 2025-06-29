package com.bytebuilder.checker.controller;

import com.bytebuilder.checker.data.model.User;
import com.bytebuilder.checker.data.repository.UserRepository;
import com.bytebuilder.checker.dto.UserDto;
import com.bytebuilder.checker.dto.request.*;
import com.bytebuilder.checker.dto.response.FoundResponse;
import com.bytebuilder.checker.dto.response.LoginResponse;
import com.bytebuilder.checker.dto.response.UploadResponse;
import com.bytebuilder.checker.exception.*;
import com.bytebuilder.checker.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final UserRepository userRepository;
    private final RestTemplate restTemplate;
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @PostMapping("/create-user")
    public ResponseEntity<?> createUser(@RequestBody RegisterUserRequest createUserRequest) {
        try{
            return ResponseEntity.ok(userService.register(createUserRequest));
        }catch(UserNotFoundException | OtpExpiredException | InvalidOtpException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(e.getMessage());
        }

    }
    @PostMapping("/login-user")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest){
        try{
            return ResponseEntity.ok(userService.login(loginRequest));
        }catch (InvalidPasswordException | UserNotFoundException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }
    @PostMapping("/send-email-verification")
    public ResponseEntity<?> sendEmailValidationOTP(@RequestBody CreateUserRequest createUserRequest){
        try{
            return ResponseEntity.ok(userService.sendVerificationOTP(createUserRequest ));
        }catch (AlreadyExistsException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }catch (Exception e) {
            return ResponseEntity.status(500).body(e.getMessage());
        }

    }
    @PostMapping("/update-profile")
    public ResponseEntity<?> updateUserProfile(@RequestBody UpdateUserProfileRequest updateUserProfileRequest){
        try{
            return ResponseEntity.ok(userService.updateProfile(updateUserProfileRequest));

        }catch (IsNotActiveException | UserNotFoundException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(e.getMessage());
        }
    }
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ChangePasswordRequest changePasswordRequest){
        try{
            return ResponseEntity.ok(userService.resetPassword(changePasswordRequest));
        }catch (UserNotFoundException | OtpExpiredException | InvalidOtpException e) {
            return ResponseEntity.badRequest().body(e.getMessage());}
        catch (Exception e) {
            return ResponseEntity.status(500).body(e.getMessage());
        }

    }
    @PostMapping("/send-reset-otp")
    public ResponseEntity<?> sendResetOTP(@RequestBody ResetPasswordRequest resetPasswordRequest){
        try{
            return ResponseEntity.ok(userService.sendResetOtp(resetPasswordRequest));
        }catch (UserNotFoundException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }catch (Exception e){
            return ResponseEntity.status(500).body(e.getMessage());
        }

    }
    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> findUserById(@PathVariable String userId){
        FoundResponse userFound = userService.findUserById(userId);
        Optional<User> existingUser = userRepository.findById(userFound.getId());
        if(existingUser.isEmpty()){
            return ResponseEntity.notFound().build();
        }
        User user = existingUser.get();
        UserDto dto = new UserDto(user.getId(), user.getEmail(), user.getRole().name());
        return ResponseEntity.ok(dto);
    }
    @PostMapping("/google")
    public ResponseEntity<LoginResponse> googleLogin(@RequestBody GoogleLoginRequest request) {
        try {
            String accessToken = request.getToken();
            String role = request.getRole();

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> googleResponse = restTemplate.exchange(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            if (!googleResponse.getStatusCode().is2xxSuccessful()) {
                throw new IllegalArgumentException("Invalid Google access token");
            }

            Map<String, Object> userInfo = googleResponse.getBody();
            assert userInfo != null;
            String email = (String) userInfo.get("email");
            String name = (String) userInfo.get("name");

            if (email == null || name == null) {
                throw new IllegalArgumentException("Failed to get user info from Google");
            }

            LoginResponse loginResponse = userService.handleGoogleLogin(email, name, role);
            return ResponseEntity.ok(loginResponse);

        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(new LoginResponse(null, null, e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new LoginResponse(null, null, "Internal server error"));
        }
    }

}