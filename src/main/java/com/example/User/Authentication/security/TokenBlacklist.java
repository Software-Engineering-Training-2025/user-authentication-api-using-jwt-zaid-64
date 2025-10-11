package com.example.User.Authentication.security;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TokenBlacklist {
    private final Map<String, Instant> banned = new ConcurrentHashMap<>();

    public void ban(String token, Instant expiresAt) {
        banned.put(token, expiresAt);
    }

    public boolean isBanned(String token) {
        Instant exp = banned.get(token);
        if (exp == null) return false;
        if (exp.isBefore(Instant.now())) {
            banned.remove(token);
            return false;
        }
        return true;
    }
}
