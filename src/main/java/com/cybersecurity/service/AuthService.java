
package com.cybersecurity.service;

import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;
import com.cybersecurity.repository.SecurityLogRepository;

public class AuthService {

    private final PasswordService passwordService;
    private final UserRepository userRepository;
    private final SecurityLogRepository securityLogRepository;
    private final PasswordValidator passwordValidator;
    private final LoginRateLimiter loginRateLimiter;

    public AuthService() {

        this.passwordService = new PasswordService();
        this.userRepository = new UserRepository();
        this.securityLogRepository = new SecurityLogRepository();
        this.passwordValidator = new PasswordValidator();
        this.loginRateLimiter = new LoginRateLimiter();
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

        return user;
    }

    /*
     * Existing login method.
     *
     * This keeps your current tests and existing application
     * working. If no IP address is provided, UNKNOWN is used.
     */
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

    /*
     * New login method that accepts an IP address.
     */
    public boolean login(
            String username,
            String password,
            String ipAddress
    ) {

        /*
         * Check whether the user has exceeded
         * the login rate limit.
         */
        if (!loginRateLimiter.isAllowed(username)) {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_RATE_LIMITED",
                    ipAddress
            );

            return false;
        }

        /*
         * Record this login attempt.
         */
        loginRateLimiter.recordAttempt(username);

        /*
         * Find the user in the database.
         */
        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        /*
         * User does not exist.
         */
        if (user == null) {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_FAILED_USER_NOT_FOUND",
                    ipAddress
            );

            return false;
        }

        /*
         * Account is already locked.
         */
        if (user.isLocked()) {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_FAILED_ACCOUNT_LOCKED",
                    ipAddress
            );

            return false;
        }

        /*
         * Check the supplied password against
         * the stored BCrypt password hash.
         */
        boolean correctPassword =
                passwordService.verifyPassword(
                        password,
                        user.getPasswordHash()
                );

        /*
         * Successful login.
         */
        if (correctPassword) {

            user.resetFailedAttempts();

            userRepository.updateSecurityStatus(user);

            /*
             * Successful login resets the rate limiter.
             */
            loginRateLimiter.reset(username);

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_SUCCESS",
                    ipAddress
            );

            return true;
        }

        /*
         * Incorrect password.
         */
        user.incrementFailedAttempts();

        /*
         * Lock the account after three failed
         * password attempts.
         */
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

        /*
         * Save the updated failed-attempt count
         * and locked status.
         */
        userRepository.updateSecurityStatus(user);

        return false;
    }
}

