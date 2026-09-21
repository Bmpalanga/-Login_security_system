package com.cybersecurity.service;

import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;
import com.cybersecurity.repository.SecurityLogRepository;

public class AuthService {

    private final PasswordService passwordService;
    private final UserRepository userRepository;
    private final SecurityLogRepository securityLogRepository;

    public AuthService() {
        this.passwordService = new PasswordService();
        this.userRepository = new UserRepository();
        this.securityLogRepository = new SecurityLogRepository();
    }
    public User registerUser(int id, String username, String password) {

        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException(
                    "Username already exists."
            );
        }

        String passwordHash =
                passwordService.hashPassword(password);

        User user = new User(
                id,
                username,
                passwordHash
        );

        userRepository.save(user);

        return user;
    }

    public boolean login(String username, String password) {

        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        if (user == null) {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_FAILED_USER_NOT_FOUND"
            );

            return false;
        }

        if (user.isLocked()) {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_FAILED_ACCOUNT_LOCKED"
            );

            return false;
        }

        boolean correctPassword =
                passwordService.verifyPassword(
                        password,
                        user.getPasswordHash()
                );

        if (correctPassword) {

            user.resetFailedAttempts();

            userRepository.updateSecurityStatus(user);

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_SUCCESS"
            );

            return true;
        }

        user.incrementFailedAttempts();

        if (user.getFailedAttempts() >= 3) {

            user.lockAccount();

            securityLogRepository.saveLog(
                    username,
                    "ACCOUNT_LOCKED"
            );

        } else {

            securityLogRepository.saveLog(
                    username,
                    "LOGIN_FAILED_WRONG_PASSWORD"
            );
        }

        userRepository.updateSecurityStatus(user);

        return false;
    }
}