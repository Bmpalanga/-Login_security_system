package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.model.User;
import com.cybersecurity.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class AuthServiceDatabaseTest {

    @BeforeEach
    void setUp() {
        DatabaseInitializer.initializeDatabase();
    }

    @Test
    void registerUserShouldCreateUser() {

        AuthService authService = new AuthService();

        User user = authService.registerUser(
                100,
                "testuser",
                "MyPassword123"
        );

        assertNotNull(user);
        assertEquals("testuser", user.getUsername());

        assertNotNull(user.getPasswordHash());

        assertNotEquals(
                "MyPassword123",
                user.getPasswordHash()
        );
    }
    @Test
    void duplicateUsernameShouldBeRejected() {

        AuthService authService = new AuthService();

        authService.registerUser(
                300,
                "uniqueUser",
                "Password123"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> authService.registerUser(
                        301,
                        "uniqueUser",
                        "AnotherPassword123"
                )
        );
    }
}