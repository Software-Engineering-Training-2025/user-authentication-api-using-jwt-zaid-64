package com.example.User.Authentication.controller;

import com.example.User.Authentication.model.User;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class UserController {

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal User u) {
        return Map.of("username", u.getUsernameField(), "email", u.getEmail());
    }
}
