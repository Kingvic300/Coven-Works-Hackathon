package com.bytebuilder.checker.service;

import com.bytebuilder.checker.data.enums.Role;
import com.bytebuilder.checker.data.model.OTP;
import com.bytebuilder.checker.data.model.PendingUser;
import com.bytebuilder.checker.data.model.User;
import com.bytebuilder.checker.data.repository.OTPRepository;
import com.bytebuilder.checker.data.repository.PendingUserRepository;
import com.bytebuilder.checker.data.repository.UserRepository;
import com.bytebuilder.checker.dto.request.*;
import com.bytebuilder.checker.dto.response.*;
import com.bytebuilder.checker.exception.*;
import com.bytebuilder.checker.mapper.UserMapper;
import com.bytebuilder.checker.util.JwtUtil;
import com.bytebuilder.checker.util.OTPGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final PendingUserRepository pendingUserRepository;
    private final JwtUtil jwtTokenUtil;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final OTPRepository otpRepository;


    @Override
    public OTPResponse sendVerificationOTP(CreateUserRequest request) {
        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());
        if (existingUser.isPresent()) {
            throw new AlreadyExistsException("Email Already in use");
        }
        validateRegisterRequest(request);
        validateEmail(request.getEmail());

        String otp = OTPGenerator.generateOtp();
        LocalDateTime expirationTime = LocalDateTime.now().plusMinutes(2);
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        PendingUser pendingUser = new PendingUser();
        pendingUser.setId(UUID.randomUUID().toString());
        pendingUser.setEmail(request.getEmail());
        pendingUser.setPassword(encodedPassword);
        pendingUser.setOtp(otp);
        pendingUser.setRole(request.getRole());
        pendingUser.setExpiryTime(expirationTime);

        pendingUserRepository.save(pendingUser);

        emailService.sendEmail(request.getEmail(), otp);

        return UserMapper.mapToOtpSentResponse("OTP sent successfully. Please verify to complete registration.", request.getEmail());
    }

    @Override
    public CreatedUserResponse register(RegisterUserRequest request) {
        PendingUser pendingUser = pendingUserRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!pendingUser.getOtp().equals(request.getOtp())) {
            throw new InvalidOtpException("Invalid OTP");
        }

        if (pendingUser.getExpiryTime().isBefore(LocalDateTime.now())) {
            throw new OtpExpiredException("OTP expired");
        }

        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setEmail(pendingUser.getEmail());
        user.setPassword(pendingUser.getPassword());
        user.setRole(pendingUser.getRole());
        user.setRegistrationDate(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        user.setActive(true);
        user.setGoogleUser(false);
        userRepository.save(user);
        var jwtToken = jwtTokenUtil.generateToken(user);


        pendingUserRepository.delete(pendingUser);

        return UserMapper.mapToCreatedUserResponse(jwtToken,user,"Registration Successful");
    }
    @Override
    public LoginResponse login(LoginRequest loginRequest){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(), loginRequest.getPassword()));
        Optional<User> existingUser = userRepository.findByEmail(loginRequest.getEmail());
        if (existingUser.isEmpty()) {
            throw new UserNotFoundException("User not found with email");
        }
        User user = existingUser.get();
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new InvalidPasswordException("Invalid password");
        }
        if(loginRequest.getRole() != null && !loginRequest.getRole().equals(user.getRole())) {
            throw new InvalidRoleException("Invalid role for user");
        }
        user.setActive(true);
        var jwtToken = jwtTokenUtil.generateToken(user);
        return UserMapper.mapToLoginResponse(jwtToken, "Login was successful", user);
    }

    @Override
    public UpdateUserProfileResponse updateProfile(UpdateUserProfileRequest updateUserProfileRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("No authenticated user found");
        }

        String email = authentication.getName();
        log.error(email);
        Optional<User> existingUser = userRepository.findByEmail(email);
        if (existingUser.isEmpty()) {
            throw new UserNotFoundException("User not found with username");
        }
        User user = existingUser.get();
        if (!user.isActive()) {
            throw new IsNotActiveException("Account has been deactivated");
        }
        UserMapper.mapToUpdateProfile(updateUserProfileRequest, user);

        userRepository.save(user);
        var token = jwtTokenUtil.generateToken(user);
        return UserMapper.mapToUpdateUserProfileResponse(token, "User profile updated successfully");
    }

    @Override
    public ResetPasswordResponse resetPassword(ChangePasswordRequest changePasswordRequest) {
        Optional<OTP> optionalOtp = otpRepository.findByEmailAndOtp(changePasswordRequest.getEmail(), changePasswordRequest.getOtp());

        if (optionalOtp.isEmpty()) {

            throw new InvalidOtpException("Invalid OTP");
        }
        OTP otp = optionalOtp.get();
        if (otp.getExpiresAt().isBefore(LocalDateTime.now())) {
            otpRepository.delete(otp);
            throw new OtpExpiredException("OTP has expired");
        }
        User user = userRepository.findByEmail(changePasswordRequest.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        String encodedPassword = passwordEncoder.encode(changePasswordRequest.getNewPassword());
        user.setPassword(encodedPassword);
        userRepository.save(user);

        otpRepository.delete(otp);
        return UserMapper.mapToResetPasswordResponse("Password reset successful", otp.getOtp(), changePasswordRequest.getEmail());
    }
    @Override
    public ResetPasswordResponse sendResetOtp(ResetPasswordRequest resetPasswordRequest){
        Optional<User> user = userRepository.findByEmail(resetPasswordRequest.getEmail());
        if (user.isEmpty()) {
            throw new UserNotFoundException("User not found");
        }
        OTP otp = new OTP();
        otp.setId(UUID.randomUUID().toString());
        otp.setOtp(OTPGenerator.generateOtp());
        otp.setEmail(resetPasswordRequest.getEmail());
        otp.setExpiresAt(LocalDateTime.now().plusMinutes(30));
        otpRepository.save(otp);
        emailService.sendResetPasswordEmail(resetPasswordRequest.getEmail(), otp.getOtp());
        System.out.println(otp);
        return UserMapper.mapToResetPasswordResponse("PendingUser sent Successfully", otp.getOtp(), resetPasswordRequest.getEmail());
    }
    @Override
    public FoundResponse findUserById(String id){
        Optional<User> user = userRepository.findById(id);
            if(user.isEmpty()){
                throw new UserNotFoundException("User not found with id");
            }
        return UserMapper.mapToFoundResponse("User found", user.get().getId());
    }
    @Override
    public LoginResponse handleGoogleLogin(String email, String name, String roleStr) {

        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("PendingUser cannot be empty");
        }
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Name cannot be empty");
        }
        if (roleStr == null) {
            throw new IllegalArgumentException("Role cannot be null");
        }

        Role role = Role.valueOf(roleStr);;

        Optional<User> userOpt = userRepository.findByEmail(email);
        User user;
        if (userOpt.isPresent()) {
            user = userOpt.get();
            if (!user.isGoogleUser()) {
                throw new IllegalStateException("PendingUser is registered with a password-based account. Please use password login.");
            }
        } else {
            user = new User();
            user.setEmail(email);
            user.setFullName(name);
            user.setRole(role);
            user.setGoogleUser(true);
            user.setActive(true);
            user = userRepository.save(user);
            System.out.println(user);
        }

        var jwtToken = jwtTokenUtil.generateToken(user);
        return UserMapper.mapToLoginResponse(jwtToken, "Login was successful", user);
    }

    private void validateEmail(String email) {
        Optional<User> foundUser = userRepository.findByEmail(email);
        if (foundUser.isPresent()) {
            throw new AlreadyExistsException("PendingUser already registered");
        }
    }
    private void validateRegisterRequest(CreateUserRequest request) {
        if (request.getEmail() == null || request.getEmail().isEmpty()) {
            throw new IllegalArgumentException("PendingUser cannot be empty");
        }
        if (request.getPassword() == null || request.getPassword().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
    }
}
