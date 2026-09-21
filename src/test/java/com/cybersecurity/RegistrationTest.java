package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;
import com.cybersecurity.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class RegistrationTest {

    private AuthService authService;
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {

        DatabaseManager.setDatabaseUrl(
                "jdbc:sqlite:login_security_test.db"
        );

        DatabaseInitializer.initializeDatabase();

        userRepository = new UserRepository();
        userRepository.deleteAll();

        authService = new AuthService();
    }

    @Test
    void shouldRegisterValidUser() {

        User user = authService.registerUser(
                1,
                "newUser",
                "Password123!"
        );

        assertNotNull(user);

        assertEquals(
                "newUser",
                user.getUsername()
        );

        assertEquals(
                0,
                user.getFailedAttempts()
        );

        assertFalse(user.isLocked());
    }

    @Test
    void shouldRejectWeakPassword() {

        assertThrows(
                IllegalArgumentException.class,
                () -> authService.registerUser(
                        2,
                        "weakUser",
                        "password"
                )
        );
    }

    @Test
    void shouldRejectDuplicateUsername() {

        authService.registerUser(
                3,
                "duplicateUser",
                "Password123!"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> authService.registerUser(
                        4,
                        "duplicateUser",
                        "Password123!"
                )
        );
    }
}