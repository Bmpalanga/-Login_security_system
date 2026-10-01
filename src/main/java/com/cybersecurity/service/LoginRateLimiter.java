package com.cybersecurity.service;

import java.util.HashMap;
import java.util.Map;

public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS = 5;

    private static final long TIME_WINDOW_MILLIS =
            60_000;

    private final Map<String, Integer> attempts =
            new HashMap<>();

    private final Map<String, Long> firstAttemptTime =
            new HashMap<>();

    public boolean isAllowed(String username) {

        if (!attempts.containsKey(username)) {
            return true;
        }

        long currentTime =
                System.currentTimeMillis();

        long firstAttempt =
                firstAttemptTime.get(username);

        if (currentTime - firstAttempt
                >= TIME_WINDOW_MILLIS) {

            reset(username);

            return true;
        }

        return attempts.get(username) < MAX_ATTEMPTS;
    }

    public void recordAttempt(String username) {

        long currentTime =
                System.currentTimeMillis();

        if (!attempts.containsKey(username)) {

            attempts.put(username, 0);

            firstAttemptTime.put(
                    username,
                    currentTime
            );
        }

        attempts.put(
                username,
                attempts.get(username) + 1
        );
    }

    public void reset(String username) {

        attempts.remove(username);
        firstAttemptTime.remove(username);
    }
}