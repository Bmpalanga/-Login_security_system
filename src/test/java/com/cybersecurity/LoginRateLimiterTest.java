package com.cybersecurity;

import com.cybersecurity.service.LoginRateLimiter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class LoginRateLimiterTest {

    @Test
    void shouldAllowFirstFiveAttempts() {

        LoginRateLimiter limiter =
                new LoginRateLimiter();

        String username = "testUser";

        for (int i = 0; i < 5; i++) {

            assertTrue(
                    limiter.isAllowed(username)
            );

            limiter.recordAttempt(username);
        }
    }

    @Test
    void shouldBlockAfterFiveAttempts() {

        LoginRateLimiter limiter =
                new LoginRateLimiter();

        String username = "blockedUser";

        for (int i = 0; i < 5; i++) {
            limiter.recordAttempt(username);
        }

        assertFalse(
                limiter.isAllowed(username)
        );
    }

    @Test
    void shouldResetAttemptsAfterSuccessfulLogin() {

        LoginRateLimiter limiter =
                new LoginRateLimiter();

        String username = "resetUser";

        for (int i = 0; i < 5; i++) {
            limiter.recordAttempt(username);
        }

        assertFalse(
                limiter.isAllowed(username)
        );

        limiter.reset(username);

        assertTrue(
                limiter.isAllowed(username)
        );
    }
}