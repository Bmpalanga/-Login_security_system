package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;
import com.cybersecurity.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class AuthServiceDatabaseTest {

    @BeforeEach
    void setUp() {

        DatabaseManager.setDatabaseUrl(
                "jdbc:sqlite:login_security_test.db"
        );

        DatabaseInitializer.initializeDatabase();

        UserRepository userRepository =
                new UserRepository();

        userRepository.deleteAll();

        AuthService authService = new AuthService();
    }
    @Test
    void registerUserShouldCreateUser() {

        AuthService authService = new AuthService();

        User user = authService.registerUser(
                100,
                "testuser",
                "MyPassword123!"
        );

        assertNotNull(user);
        assertEquals("testuser", user.getUsername());

        assertNotNull(user.getPasswordHash());

        assertNotEquals(
                "MyPassword123!",
                user.getPasswordHash()
        );
    }
    @Test
    void duplicateUsernameShouldBeRejected() {

        AuthService authService = new AuthService();

        authService.registerUser(
                300,
                "uniqueUser",
                "Password123!"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> authService.registerUser(
                        301,
                        "uniqueUser",
                        "AnotherPassword123!"
                )
        );
    }
}