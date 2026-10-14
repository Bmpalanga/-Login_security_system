
package com.cybersecurity.service;

import com.cybersecurity.model.User;
import com.cybersecurity.repository.PasswordHistoryRepository;
import com.cybersecurity.repository.UserRepository;
import com.cybersecurity.repository.SecurityLogRepository;
import com.cybersecurity.repository.PasswordHistoryRepository;


public class AuthService {

    private final PasswordService passwordService;
    private final UserRepository userRepository;
    private final SecurityLogRepository securityLogRepository;
    private final PasswordValidator passwordValidator;
    private final LoginRateLimiter loginRateLimiter;
    private final AccountLockService accountLockService;
    private final PasswordHistoryRepository passwordHistoryRepository;

    public AuthService() {

        this.passwordService = new PasswordService();
        this.userRepository = new UserRepository();
        this.securityLogRepository = new SecurityLogRepository();
        this.passwordValidator = new PasswordValidator();
        this.loginRateLimiter = new LoginRateLimiter();
        this.accountLockService = new AccountLockService();
        this.passwordHistoryRepository = new PasswordHistoryRepository();
    }

    public User registerUser(
            int id,
            String username,
            String password
    ) {


        if (userRepository.findByUsername(username).isPresent()) {

            throw new IllegalArgumentException(
                    "Username already exists."
            );
        }

        if (!passwordValidator.isStrong(password)) {

            throw new IllegalArgumentException(
                    "Password does not meet security requirements."
            );
        }

        String passwordHash =
                passwordService.hashPassword(password);

        User user =
                new User(id, username, passwordHash);


        userRepository.save(user);

        passwordHistoryRepository.savePassword(
                username,
                passwordHash
        );

        return user;


    }

    public boolean login(
            String username,
            String password
    ) {

        return login(
                username,
                password,
                "UNKNOWN"
        );
    }

    public boolean login(
            String username,
            String password,
            String ipAddress
    ) {

        if (!loginRateLimiter.isAllowed(username)) {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_RATE_LIMITED",
                    ipAddress
            );

            return false;
        }

        loginRateLimiter.recordAttempt(username);

        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        if (user == null) {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_FAILED_USER_NOT_FOUND",
                    ipAddress
            );

            return false;
        }

        if (user.isLocked()) {

            boolean unlocked =
                    accountLockService.unlockIfExpired(user);

            if (!unlocked) {

                securityLogRepository.saveLog(
                        username,
                        "LOGIN_FAILED_ACCOUNT_LOCKED",
                        ipAddress
                );

                return false;
            }

            securityLogRepository.saveLog(
                    username,
                    "ACCOUNT_AUTO_UNLOCKED",
                    ipAddress
            );
        }

        boolean correctPassword =
                passwordService.verifyPassword(
                        password,
                        user.getPasswordHash()
                );

        if (correctPassword) {

            user.resetFailedAttempts();

            userRepository.updateSecurityStatus(user);

            loginRateLimiter.reset(username);

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_SUCCESS",
                    ipAddress
            );

            return true;
        }

        user.incrementFailedAttempts();

        if (user.getFailedAttempts() >= 3) {

            user.lockAccount();

            securityLogRepository.saveLog(
                    username,
                    "ACCOUNT_LOCKED",
                    ipAddress
            );

        } else {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_FAILED_WRONG_PASSWORD",
                    ipAddress
            );
        }

        userRepository.updateSecurityStatus(user);

        return false;
    }


    public void changePassword(
            String username,
            String newPassword
    ) {

        User user = userRepository
                .findByUsername(username)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "User not found."
                        )
                );

        if (!passwordValidator.isStrong(newPassword)) {

            throw new IllegalArgumentException(
                    "Password does not meet security requirements."
            );
        }

        if (passwordHistoryRepository.hasUsedPassword(
                username,
                newPassword
        )) {

            throw new IllegalArgumentException(
                    "Password has already been used."
            );
        }

        String newPasswordHash =
                passwordService.hashPassword(newPassword);

        userRepository.updatePassword(
                username,
                newPasswordHash
        );

        passwordHistoryRepository.savePassword(
                username,
                newPasswordHash
        );
        securityLogRepository.saveLog(
                username,
                "PASSWORD_CHANGED"
        );
    }

}