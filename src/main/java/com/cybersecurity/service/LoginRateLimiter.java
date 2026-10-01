package com.cybersecurity.service;

import java.util.HashMap;
import java.util.Map;

public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS = 5;

    private final Map<String, Integer> attempts =
            new HashMap<>();

    public boolean isAllowed(String username) {

        int currentAttempts =
                attempts.getOrDefault(username, 0);

        return currentAttempts < MAX_ATTEMPTS;
    }

    public void recordAttempt(String username) {

        int currentAttempts =
                attempts.getOrDefault(username, 0);

        attempts.put(
                username,
                currentAttempts + 1
        );
    }

    public void reset(String username) {

        attempts.remove(username);
    }
}