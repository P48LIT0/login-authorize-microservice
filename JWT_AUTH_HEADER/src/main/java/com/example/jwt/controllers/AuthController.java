package com.example.jwt.controllers;

import javax.validation.Valid;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.jwt.service.ManageUserService;
import com.example.jwt.payload.LoginRequest;
import com.example.jwt.payload.SignupRequest;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/vi")
@RequiredArgsConstructor
public class AuthController {

    private final ManageUserService manageUserService;

    @PostMapping("/login")
    public ResponseEntity authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
       return manageUserService.authenticateUserService(loginRequest);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return manageUserService.registerUserService(signUpRequest);
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        return manageUserService.signoutUserService();
    }

    @GetMapping ("/hello")
    public ResponseEntity<?> hello() {
        return manageUserService.hello();
    }
}
