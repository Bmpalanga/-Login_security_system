package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class LoginTest {

    private AuthService authService;

    @BeforeEach
    void setUp() {
        DatabaseInitializer.initializeDatabase();
        authService = new AuthService();
    }

    @Test
    void correctPasswordShouldAllowLogin() {

        authService.registerUser(
                400,
                "loginUser",
                "Password123"
        );

        boolean result = authService.login(
                "loginUser",
                "Password123"
        );

        assertTrue(result);
    }
    @Test
    void wrongPasswordShouldRejectLogin() {

        authService.registerUser(
                401,
                "wrongPasswordUser",
                "Password123"
        );

        boolean result = authService.login(
                "wrongPasswordUser",
                "WrongPassword"
        );

        assertFalse(result);
    }
    @Test
    void accountShouldLockAfterThreeFailedAttempts() {

        authService.registerUser(
                402,
                "lockedUser",
                "Password123"
        );

        assertFalse(
                authService.login(
                        "lockedUser",
                        "WrongPassword"
                )
        );

        assertFalse(
                authService.login(
                        "lockedUser",
                        "WrongPassword"
                )
        );

        assertFalse(
                authService.login(
                        "lockedUser",
                        "WrongPassword"
                )
        );

        // Correct password should now fail
        // because the account is locked.
        assertFalse(
                authService.login(
                        "lockedUser",
                        "Password123"
                )
        );
    }
}