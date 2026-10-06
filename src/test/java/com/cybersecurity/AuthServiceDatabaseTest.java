
        package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.model.User;
import com.cybersecurity.repository.SecurityLogRepository;
import com.cybersecurity.repository.UserRepository;
import com.cybersecurity.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.cybersecurity.service.AdminService;

import java.util.List;

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

        SecurityLogRepository securityLogRepository =
                new SecurityLogRepository();

        securityLogRepository.deleteAll();
    }

    @Test
    void registerUserShouldCreateUser() {

        AuthService authService =
                new AuthService();

        User user = authService.registerUser(
                100,
                "testuser",
                "MyPassword123!"
        );

        assertNotNull(user);

        assertEquals(
                "testuser",
                user.getUsername()
        );

        assertNotNull(
                user.getPasswordHash()
        );

        assertNotEquals(
                "MyPassword123!",
                user.getPasswordHash()
        );
    }

    @Test
    void duplicateUsernameShouldBeRejected() {

        AuthService authService =
                new AuthService();

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

    @Test
    void loginShouldRecordIpAddress() {

        AuthService authService =
                new AuthService();

        SecurityLogRepository securityLogRepository =
                new SecurityLogRepository();

        /*
         * Register the user.
         */
        authService.registerUser(
                400,
                "ipTestUser",
                "Password123!"
        );

        /*
         * Login using an IP address.
         */
        boolean loginSuccessful =
                authService.login(
                        "ipTestUser",
                        "Password123!",
                        "192.168.1.10"
                );

        /*
         * Login should succeed.
         */
        assertTrue(loginSuccessful);

        /*
         * Retrieve the security logs.
         */
        List<String> logs =
                securityLogRepository
                        .findLogsByUsername("ipTestUser");

        /*
         * There should be one login log.
         */
        assertEquals(
                1,
                logs.size()
        );

        /*
         * The log should contain the successful
         * login event.
         */
        assertTrue(
                logs.get(0).contains(
                        "LOGIN_SUCCESS"
                )
        );

        /*
         * The log should contain the IP address.
         */
        assertTrue(
                logs.get(0).contains(
                        "192.168.1.10"
                )
        );
    }

    @Test
    void accountLockShouldRecordLockedAtTimestamp() {

        AuthService authService =
                new AuthService();

        UserRepository userRepository =
                new UserRepository();

        authService.registerUser(
                500,
                "lockTimeUser",
                "Password123!"
        );

        // Three incorrect passwords should lock the account.
        authService.login(
                "lockTimeUser",
                "WrongPassword123!",
                "192.168.1.20"
        );

        authService.login(
                "lockTimeUser",
                "WrongPassword123!",
                "192.168.1.20"
        );

        authService.login(
                "lockTimeUser",
                "WrongPassword123!",
                "192.168.1.20"
        );

        User lockedUser =
                userRepository
                        .findByUsername("lockTimeUser")
                        .orElseThrow();

        assertTrue(
                lockedUser.isLocked()
        );

        assertNotNull(
                lockedUser.getLockedAt()
        );

        assertFalse(
                lockedUser.getLockedAt().isBlank()
        );
    }

    @Test
    void adminShouldBeAbleToUnlockAccount() {

        AuthService authService =
                new AuthService();

        UserRepository userRepository =
                new UserRepository();

        AdminService adminService =
                new AdminService();

        authService.registerUser(
                600,
                "unlockTestUser",
                "Password123!"
        );

        // Three incorrect passwords lock the account.
        authService.login(
                "unlockTestUser",
                "WrongPassword123!",
                "192.168.1.30"
        );

        authService.login(
                "unlockTestUser",
                "WrongPassword123!",
                "192.168.1.30"
        );

        authService.login(
                "unlockTestUser",
                "WrongPassword123!",
                "192.168.1.30"
        );

        User lockedUser =
                userRepository
                        .findByUsername("unlockTestUser")
                        .orElseThrow();

        assertTrue(
                lockedUser.isLocked()
        );

        assertNotNull(
                lockedUser.getLockedAt()
        );

        // Administrator unlocks the account.
        adminService.unlockUser(
                "unlockTestUser"
        );

        User unlockedUser =
                userRepository
                        .findByUsername("unlockTestUser")
                        .orElseThrow();

        assertFalse(
                unlockedUser.isLocked()
        );

        assertEquals(
                0,
                unlockedUser.getFailedAttempts()
        );

        assertNull(
                unlockedUser.getLockedAt()
        );

        // User should be able to log in again.
        boolean loginSuccessful =
                authService.login(
                        "unlockTestUser",
                        "Password123!",
                        "192.168.1.30"
                );

        assertTrue(loginSuccessful);
    }




}

