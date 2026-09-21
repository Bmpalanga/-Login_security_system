package com.cybersecurity.service;

import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;

public class AuthService {

    private final PasswordService passwordService;
    private final UserRepository userRepository;

    public AuthService() {
        this.passwordService = new PasswordService();
        this.userRepository = new UserRepository();
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

        // Find the user
        User user = userRepository
                .findByUsername(username)
                .orElse(null);

        // User does not exist
        if (user == null) {
            return false;
        }

        // Account is already locked
        if (user.isLocked()) {
            return false;
        }

        // Check password
        boolean correctPassword =
                passwordService.verifyPassword(
                        password,
                        user.getPasswordHash()
                );

        if (correctPassword) {

            // Successful login
            user.resetFailedAttempts();

            // Save reset to database
            userRepository.updateSecurityStatus(user);

            return true;
        }

        // Wrong password
        user.incrementFailedAttempts();

        // Lock after 3 failed attempts
        if (user.getFailedAttempts() >= 3) {
            user.lockAccount();
        }

        // Save failed attempts and lock status
        userRepository.updateSecurityStatus(user);

        return false;
    }
}