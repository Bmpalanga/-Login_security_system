package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;
import com.cybersecurity.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class LoginTest {

    private AuthService authService;

    @BeforeEach
    void setUp() {

        DatabaseManager.setDatabaseUrl(
                "jdbc:sqlite:login_security_test.db"
        );

        DatabaseInitializer.initializeDatabase();

        UserRepository userRepository =
                new UserRepository();

        userRepository.deleteAll();

        authService = new AuthService();
    }

    @Test
    void correctPasswordShouldAllowLogin() {

        authService.registerUser(
                400,
                "loginUser",
                "Password123!"
        );

        boolean result = authService.login(
                "loginUser",
                "Password123!"
        );

        assertTrue(result);
    }

    @Test
    void wrongPasswordShouldRejectLogin() {

        authService.registerUser(
                401,
                "wrongPasswordUser",
                "Password123!"
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
                "Password123!"
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

        assertFalse(
                authService.login(
                        "lockedUser",
                        "Password123!"
                )
        );
    }
    @Test
    void shouldLockAccountAfterThreeFailedLoginAttempts() {

        authService.registerUser(
                10,
                "lockUser",
                "Password123!"
        );

        assertFalse(
                authService.login(
                        "lockUser",
                        "WrongPassword1!"
                )
        );

        assertFalse(
                authService.login(
                        "lockUser",
                        "WrongPassword2!"
                )
        );

        assertFalse(
                authService.login(
                        "lockUser",
                        "WrongPassword3!"
                )
        );

        UserRepository userRepository =
                new UserRepository();

        User user = userRepository
                .findByUsername("lockUser")
                .orElseThrow();

        assertEquals(
                3,
                user.getFailedAttempts()
        );

        assertTrue(
                user.isLocked()
        );
    }
    @Test
    void shouldNotAllowLoginAfterAccountIsLocked() {

        authService.registerUser(
                11,
                "lockedUser",
                "Password123!"
        );

        authService.login(
                "lockedUser",
                "WrongPassword1!"
        );

        authService.login(
                "lockedUser",
                "WrongPassword2!"
        );

        authService.login(
                "lockedUser",
                "WrongPassword3!"
        );

        boolean loginResult =
                authService.login(
                        "lockedUser",
                        "Password123!"
                );

        assertFalse(loginResult);
    }
}