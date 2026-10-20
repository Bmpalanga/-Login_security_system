
package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.model.User;
import com.cybersecurity.repository.PasswordHistoryRepository;
import com.cybersecurity.repository.SecurityLogRepository;
import com.cybersecurity.repository.UserRepository;
import com.cybersecurity.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.cybersecurity.service.AdminService;
import com.cybersecurity.service.AccountLockService;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;


import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AuthServiceDatabaseTest {
    @BeforeEach
    void setUp() {

        // Use a separate database for testing.
        DatabaseManager.setDatabaseUrl(
                "jdbc:sqlite:login_security_test.db"
        );


        DatabaseInitializer.initializeDatabase();

        // Clear users from previous tests.
        UserRepository userRepository =
                new UserRepository();

        userRepository.deleteAll();


        SecurityLogRepository securityLogRepository =
                new SecurityLogRepository();

        securityLogRepository.deleteAll();


        PasswordHistoryRepository passwordHistoryRepository =
                new PasswordHistoryRepository();

        passwordHistoryRepository.deleteAll();
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

    @Test
    void lockedAccountShouldRemainLockedBeforeUnlockTime() {

        AuthService authService =
                new AuthService();

        UserRepository userRepository =
                new UserRepository();

        AccountLockService accountLockService =
                new AccountLockService();

        authService.registerUser(
                700,
                "autoUnlockUser",
                "Password123!"
        );

        // Three incorrect attempts lock the account.
        authService.login(
                "autoUnlockUser",
                "WrongPassword123!",
                "192.168.1.40"
        );

        authService.login(
                "autoUnlockUser",
                "WrongPassword123!",
                "192.168.1.40"
        );

        authService.login(
                "autoUnlockUser",
                "WrongPassword123!",
                "192.168.1.40"
        );

        User lockedUser =
                userRepository
                        .findByUsername("autoUnlockUser")
                        .orElseThrow();

        assertTrue(
                lockedUser.isLocked()
        );

        assertNotNull(
                lockedUser.getLockedAt()
        );

        // The account was just locked, so it should
        // not automatically unlock yet.
        boolean unlocked =
                accountLockService.unlockIfExpired(
                        lockedUser
                );

        assertFalse(unlocked);

        User stillLockedUser =
                userRepository
                        .findByUsername("autoUnlockUser")
                        .orElseThrow();

        assertTrue(
                stillLockedUser.isLocked()
        );
    }

    @Test
    void lockedAccountShouldAutomaticallyUnlockAfter15Minutes() {

        UserRepository userRepository =
                new UserRepository();

        AccountLockService accountLockService =
                new AccountLockService();

        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern(
                        "yyyy-MM-dd HH:mm:ss"
                );

        String oldLockedAt =
                LocalDateTime.now()
                        .minusMinutes(16)
                        .format(formatter);

        User lockedUser =
                new User(
                        701,
                        "expiredLockUser",
                        "Password123!",
                        3,
                        true,
                        oldLockedAt
                );

        userRepository.save(lockedUser);

        User savedUser =
                userRepository
                        .findByUsername("expiredLockUser")
                        .orElseThrow();

        assertTrue(
                savedUser.isLocked()
        );

        assertNotNull(
                savedUser.getLockedAt()
        );

        boolean unlocked =
                accountLockService.unlockIfExpired(
                        savedUser
                );

        assertTrue(unlocked);

        User unlockedUser =
                userRepository
                        .findByUsername("expiredLockUser")
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
    }

    @Test
    void userShouldBeAbleToLoginAfterAutomaticUnlock() {

        AuthService authService =
                new AuthService();

        UserRepository userRepository =
                new UserRepository();

        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern(
                        "yyyy-MM-dd HH:mm:ss"
                );

        String expiredLockedAt =
                LocalDateTime.now()
                        .minusMinutes(16)
                        .format(formatter);

        User lockedUser =
                new User(
                        702,
                        "loginAfterUnlockUser",
                        "$2a$10$abcdefghijklmnopqrstuu",
                        3,
                        true,
                        expiredLockedAt
                );

        userRepository.save(lockedUser);

        /*
         * Replace the stored password hash with a real
         * password by registering the user is not possible
         * because the username already exists.
         *
         * Instead, remove the temporary user and create
         * it through AuthService.
         */
        userRepository.deleteAll();

        authService.registerUser(
                702,
                "loginAfterUnlockUser",
                "Password123!"
        );

        User user =
                userRepository
                        .findByUsername("loginAfterUnlockUser")
                        .orElseThrow();

        user.lockAccount();

        /*
         * Move the lock timestamp back by 16 minutes.
         */
        User expiredUser =
                new User(
                        user.getId(),
                        user.getUsername(),
                        user.getPasswordHash(),
                        3,
                        true,
                        expiredLockedAt
                );

        userRepository.deleteAll();
        userRepository.save(expiredUser);

        boolean loginSuccessful =
                authService.login(
                        "loginAfterUnlockUser",
                        "Password123!",
                        "192.168.1.50"
                );

        assertTrue(loginSuccessful);

        User loggedInUser =
                userRepository
                        .findByUsername("loginAfterUnlockUser")
                        .orElseThrow();

        assertFalse(
                loggedInUser.isLocked()
        );

        assertEquals(
                0,
                loggedInUser.getFailedAttempts()
        );

        assertNull(
                loggedInUser.getLockedAt()
        );
    }

    @Test
    void shouldStoreInitialPasswordInHistory() {

        AuthService authService = new AuthService();

        authService.registerUser(
                500,
                "historyUser",
                "StrongPassword1!"
        );

        PasswordHistoryRepository repository =
                new PasswordHistoryRepository();

        assertTrue(
                repository.hasUsedPassword(
                        "historyUser",
                        "StrongPassword1!"
                )
        );
    }

    @Test
    void shouldRejectPreviouslyUsedPasswordWhenChangingPassword() {

        AuthService authService = new AuthService();

        authService.registerUser(
                600,
                "passwordChangeUser",
                "StrongPassword1!"
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        "passwordChangeUser",
                        "StrongPassword1!",
                        "StrongPassword1!"
                )
        );
    }
    @Test
    void shouldPreventReuseOfOlderPasswordsAfterMultipleChanges() {

        AuthService authService = new AuthService();

        String username = "passwordHistoryUser802";
        String originalPassword = "OriginalPassword802!";
        String secondPassword = "SecondPassword802@";
        String thirdPassword = "ThirdPassword802#";

        // Register the user with the original password.
        authService.registerUser(
                802,
                username,
                originalPassword
        );

        // Change to the second password.
        authService.changePassword(
                username,
                originalPassword,
                secondPassword
        );

        // Change to the third password.
        authService.changePassword(
                username,
                secondPassword,
                thirdPassword
        );

        // The original password must not be reusable.
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        username,
                        thirdPassword,
                        originalPassword
                )
        );

        // The second password must not be reusable either.
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        username,
                        thirdPassword,
                        secondPassword
                )
        );
    }


    @Test
    void shouldLogSuccessfulPasswordChange() {

        AuthService authService = new AuthService();

        SecurityLogRepository securityLogRepository =
                new SecurityLogRepository();

        String username = "passwordLogUser701";
        String originalPassword = "OriginalPassword701!";
        String newPassword = "ChangedPassword701!";

        authService.registerUser(
                701,
                username,
                originalPassword
        );

        authService.changePassword(
                username,
                originalPassword,
                newPassword
        );

        assertTrue(
                securityLogRepository
                        .findLogsByUsername(username)
                        .stream()
                        .anyMatch(log ->
                                log.contains("PASSWORD_CHANGED"))
        );
    }


    @Test
    void shouldAllowLoginWithNewPasswordAfterPasswordChange() {

        AuthService authService = new AuthService();

        String username = "passwordLoginChangeUser701";
        String oldPassword = "StrongPassword1!";
        String newPassword = "NewStrongPassword2@";

        authService.registerUser(
                701,
                username,
                oldPassword
        );

        authService.changePassword(
                username,
                oldPassword,
                newPassword
        );
        assertTrue(
                authService.login(
                        username,
                        newPassword
                ),
                "Login should succeed with the new password"
        );

        assertFalse(
                authService.login(
                        username,
                        oldPassword
                ),
                "Login should fail with the old password"
        );
    }
        @Test
        void shouldResetFailedAttemptsAfterPasswordChange(){

            AuthService authService = new AuthService();

            UserRepository userRepository = new UserRepository();

            String username = "resetAttemptsUser801";
            String oldPassword = "OriginalPassword801!";
            String newPassword = "NewPassword801@";

            // Register the user.
            authService.registerUser(
                    801,
                    username,
                    oldPassword
            );

            // Record one failed login attempt.
            assertFalse(
                    authService.login(
                            username,
                            "WrongPassword801!"
                    )
            );

            // Confirm that the failed attempt was recorded.
            User userBeforeChange = userRepository
                    .findByUsername(username)
                    .orElseThrow();

            assertEquals(
                    1,
                    userBeforeChange.getFailedAttempts()
            );

            // Change the password.
            authService.changePassword(
                    username,
                    oldPassword,
                    newPassword
            );
            // Confirm that failed attempts have been reset.
            User userAfterChange = userRepository
                    .findByUsername(username)
                    .orElseThrow();

            assertEquals(
                    0,
                    userAfterChange.getFailedAttempts()
            );

            // Confirm that the new password works.
            assertTrue(
                    authService.login(
                            username,
                            newPassword
                    )
            );


            assertFalse(
                    authService.login(
                            username,
                            oldPassword
                    )
            );
        }
    @Test
    void shouldKeepCurrentPasswordAfterRejectedPasswordChange() {

        AuthService authService = new AuthService();

        String username = "rejectedChangeUser803";
        String originalPassword = "OriginalPassword803!";
        String newPassword = "NewPassword803@";

        authService.registerUser(
                803,
                username,
                originalPassword
        );

        authService.changePassword(
                username,
                originalPassword,
                newPassword
        );
        // Attempt to reuse the original password.
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        username,
                        newPassword,
                        originalPassword
                )
        );

        // The current password should still work.
        assertTrue(
                authService.login(
                        username,
                        newPassword
                )
        );

        // The rejected password must not work.
        assertFalse(
                authService.login(
                        username,
                        originalPassword
                )
        );
    }
    @Test
    void shouldNotLogRejectedPasswordChangeAsSuccessful() {

        AuthService authService = new AuthService();
        SecurityLogRepository securityLogRepository =
                new SecurityLogRepository();

        String username = "rejectedLogUser804";
        String originalPassword = "OriginalPassword804!";
        String newPassword = "NewPassword804@";

        // Register the user.
        authService.registerUser(
                804,
                username,
                originalPassword
        );

        // Change the password successfully.
        authService.changePassword(
                username,
                originalPassword,
                newPassword
        );

        // Attempt to reuse the original password.
        assertThrows(
                IllegalArgumentException.class,() -> authService.changePassword(
                        username,
                        newPassword,
                        originalPassword
                )
        );

        // Only the successful change should be logged.
        long passwordChangeEvents =
                securityLogRepository
                        .findLogsByUsername(username)
                        .stream()
                        .filter(log -> log.contains("PASSWORD_CHANGED"))
                        .count();

        assertEquals(1, passwordChangeEvents);
    }
    @Test
    void shouldRejectPasswordChangeForNonexistentUser() {

        AuthService authService = new AuthService();

        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        "nonexistentUser805",
                        "CurrentPassword805!",
                        "NewPassword805@"
                )
        );
    }
    @Test
    void shouldRejectWeakPasswordAndKeepCurrentPassword() {

        AuthService authService = new AuthService();

        String username = "weakPasswordUser806";
        String originalPassword = "OriginalPassword806!";

        // Register the user.
        authService.registerUser(
                806,
                username,
                originalPassword
        );

        // Attempt to change to a weak password.
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        username,
                        originalPassword,
                        "weak"
                )
        );

        // The original password should still work.
        assertTrue(
                authService.login(
                        username,
                        originalPassword
                )
        );

        // The weak password should not work.
        assertFalse(
                authService.login(
                        username,
                        "weak"
                )
        );
    }
    @Test
    void shouldRejectPasswordChangeWithIncorrectCurrentPassword() {

        AuthService authService = new AuthService();

        String username = "incorrectCurrentPasswordUser807";
        String originalPassword = "OriginalPassword807!";
        String newPassword = "NewPassword807@";
        String incorrectPassword = "WrongPassword807!";

        // Register the user.
        authService.registerUser(
                807,
                username,
                originalPassword
        );

        // Attempt to change the password using an incorrect current password.
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        username,
                        incorrectPassword,
                        newPassword
                )
        );

        // The original password must still work.
        assertTrue(
                authService.login(
                        username,
                        originalPassword
                ),
                "The original password should still work."
        );

        // The new password must not work.
        assertFalse(
                authService.login(
                        username,
                        newPassword
                ),
                "The new password should not work."
        );
    }
    @Test
    void shouldNotLogSuccessfulPasswordChangeWhenCurrentPasswordIsIncorrect() {

        AuthService authService = new AuthService();

        SecurityLogRepository securityLogRepository =
                new SecurityLogRepository();

        String username = "incorrectPasswordLogUser808";
        String originalPassword = "OriginalPassword808!";
        String newPassword = "NewPassword808@";
        String incorrectPassword = "WrongPassword808!";

        // Register the user.
        authService.registerUser(
                808,
                username,
                originalPassword
        );

        // Attempt a password change with the wrong current password.
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        username,
                        incorrectPassword,
                        newPassword
                )
        );

        // Confirm that no successful password change was logged.
        long passwordChangeEvents =
                securityLogRepository
                        .findLogsByUsername(username)
                        .stream()
                        .filter(log -> log.contains("PASSWORD_CHANGED"))
                        .count();

        assertEquals(
                0,
                passwordChangeEvents,
                "A rejected password change must not be logged as successful."
        );

        // Confirm that the original password still works.
        assertTrue(
                authService.login(
                        username,
                        originalPassword
                )
        );

        // Confirm that the proposed new password does not work.
        assertFalse(
                authService.login(
                        username,
                        newPassword
                )
        );
    }
    @Test
    void shouldLogFailedPasswordChangeWhenCurrentPasswordIsIncorrect() {

        AuthService authService = new AuthService();

        SecurityLogRepository securityLogRepository =
                new SecurityLogRepository();

        String username = "failedPasswordChangeUser809";
        String originalPassword = "OriginalPassword809!";
        String newPassword = "NewPassword809@";
        String incorrectPassword = "WrongPassword809!";

        // Register the user.
        authService.registerUser(
                809,
                username,
                originalPassword
        );

        // Attempt to change the password with an incorrect current password.
        assertThrows(
                IllegalArgumentException.class,
                () -> authService.changePassword(
                        username,
                        incorrectPassword,
                        newPassword
                )
        );

        // Confirm that the failed password change was logged.
        assertTrue(
                securityLogRepository
                        .findLogsByUsername(username)
                        .stream()
                        .anyMatch(log ->
                                log.contains("PASSWORD_CHANGE_FAILED")),
                "The failed password change should be recorded."
        );

        // Confirm that no successful password change was logged.
        assertFalse(
                securityLogRepository
                        .findLogsByUsername(username)
                        .stream()
                        .anyMatch(log ->
                                log.contains("PASSWORD_CHANGED")),
                "A rejected password change must not be logged as successful."
        );
    }

    }



















