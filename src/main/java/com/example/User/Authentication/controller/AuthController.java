package com.example.User.Authentication.controller;

import com.example.User.Authentication.dto.AuthResponse;
import com.example.User.Authentication.dto.LoginRequest;
import com.example.User.Authentication.dto.RefreshTokenRequest;
import com.example.User.Authentication.dto.SignupRequest;
import com.example.User.Authentication.model.User;
import com.example.User.Authentication.repository.UserRepository;
import com.example.User.Authentication.security.JwtService;
import com.example.User.Authentication.security.TokenBlacklist;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final TokenBlacklist blacklist;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          TokenBlacklist blacklist) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.blacklist = blacklist;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest req) {
        if (userRepository.existsByEmail(req.getEmail()) || userRepository.existsByUsername(req.getUsername())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email or username already in use");
        }
        User u = new User();
        u.setUsername(req.getUsername());
        u.setEmail(req.getEmail());
        u.setPassword(passwordEncoder.encode(req.getPassword()));
        userRepository.save(u);

        String access = jwtService.generateAccessToken(u);
        String refresh = jwtService.generateRefreshToken(u);
        return ResponseEntity.ok(new AuthResponse(access, refresh));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword()));
        User u = (User) auth.getPrincipal();
        String access = jwtService.generateAccessToken(u);
        String refresh = jwtService.generateRefreshToken(u);
        return ResponseEntity.ok(new AuthResponse(access, refresh));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshTokenRequest req) {
        String refresh = req.getRefreshToken();
        if (blacklist.isBanned(refresh)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token is revoked");
        }
        String email;
        try {
            email = jwtService.extractUsername(refresh);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
        User u = userRepository.findByEmail(email).orElse(null);
        if (u == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        String newAccess = jwtService.generateAccessToken(u);
        String newRefresh = jwtService.generateRefreshToken(u);
        return ResponseEntity.ok(new AuthResponse(newAccess, newRefresh));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest req) {
        String refresh = req.getRefreshToken();
        Instant exp;
        try {
            exp = jwtService.extractExpirationInstant(refresh);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        blacklist.ban(refresh, exp);
        return ResponseEntity.noContent().build();
    }
}
