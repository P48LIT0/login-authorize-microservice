package com.example.jwt.service;

import com.example.jwt.exception.handler.CustomExceptionHandler;
import com.example.jwt.exception.model.RoleNotFoundException;
import com.example.jwt.exception.model.UserAlreadyExistsException;
import com.example.jwt.exception.model.UserNotFoundException;
import com.example.jwt.model.Roles;
import com.example.jwt.entities.Role;
import com.example.jwt.entities.User;
import com.example.jwt.payload.LoginRequest;
import com.example.jwt.payload.MessageResponse;
import com.example.jwt.payload.SignupRequest;
import com.example.jwt.payload.UserInfoResponse;
import com.example.jwt.repository.RoleRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.security.JwtUtils;
import com.example.jwt.security.SecurityUserImpl;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class ManageUserService {

    private AuthenticationManager authenticationManager;
    private JwtUtils jwtUtils;
    private RoleRepository roleRepository;
    private UserRepository userRepository;
    private PasswordEncoder encoder;

    public ResponseEntity<?> authenticateUserService(LoginRequest loginRequest) {
        if (userRepository.existsByUsername(loginRequest.getUsername())==false) {
            ResponseCookie cookie = jwtUtils.getCleanJwt();
            //throw new UserNotFoundException("Error: User not found!", HttpStatus.BAD_REQUEST.value());
            return ResponseEntity.ok().header("Authorization", cookie.toString())
                    .body(new CustomExceptionHandler().handleUserNotFoundException(new UserNotFoundException("Error: User not found!", HttpStatus.BAD_REQUEST.value())));
        }

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        SecurityUserImpl userDetails = (SecurityUserImpl) authentication.getPrincipal();
        User user = userDetails.getUser();
        ResponseCookie jwtCookie = jwtUtils.generateJwt(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok()
                .body(new UserInfoResponse(user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        roles,
                        jwtCookie.getValue()));
    }

    public ResponseEntity<?> registerUserService(SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            ResponseCookie cookie = jwtUtils.getCleanJwt();
//            throw new UserAlreadyExistsException("Error: Username is already taken!", HttpStatus.BAD_REQUEST.value());
            return ResponseEntity.ok().header("Authorization", cookie.toString())
                    .body(new CustomExceptionHandler().handleUserAlreadyExistsException(new UserAlreadyExistsException("Error: Username is already taken!", HttpStatus.BAD_REQUEST.value())));
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            ResponseCookie cookie = jwtUtils.getCleanJwt();
//            throw new UserAlreadyExistsException("Error: Email is already in use!", HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.ok().header("Authorization", cookie.toString())
                .body(new CustomExceptionHandler().handleUserAlreadyExistsException(new UserAlreadyExistsException("Error: Email is already taken!", HttpStatus.BAD_REQUEST.value())));
        }

        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));
        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(Roles.ROLE_USER)
                    .orElseThrow(() -> new RoleNotFoundException("Error: Role is not found.", HttpStatus.NOT_FOUND.value()));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(Roles.ROLE_ADMIN)
                                .orElseThrow(() -> new RoleNotFoundException("Error: Role is not found.", HttpStatus.NOT_FOUND.value()));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(Roles.ROLE_MODERATOR)
                                .orElseThrow(() -> new RoleNotFoundException("Error: Role is not found.", HttpStatus.NOT_FOUND.value()));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(Roles.ROLE_USER)
                                .orElseThrow(() -> new RoleNotFoundException("Error: Role is not found.", HttpStatus.NOT_FOUND.value()));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(signUpRequest.getUsername(), signUpRequest.getPassword()));
        SecurityUserImpl userDetails = (SecurityUserImpl) authentication.getPrincipal();
        List<String> roles1 = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        return ResponseEntity.ok()
                .body(new UserInfoResponse(user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        roles1,
                        null));
    }

    public ResponseEntity<?> signoutUserService() {
        ResponseCookie cookie = jwtUtils.getCleanJwt();
        return ResponseEntity.ok().header("Authorization", cookie.toString())
                .body(new MessageResponse(HttpStatus.OK.value(),"You've been signed out!"));
    }

    public ResponseEntity<?> hello() {
        return ResponseEntity.ok().body("WELCOME AUTHENTICATED USER");
    }
}
