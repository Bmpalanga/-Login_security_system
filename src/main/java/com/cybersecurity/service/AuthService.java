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

        // Check if username already exists
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException(
                    "Username already exists."
            );
        }

        // Hash password
        String passwordHash = passwordService.hashPassword(password);

        // Create user
        User user = new User(
                id,
                username,
                passwordHash
        );

        // Save user
        userRepository.save(user);

        return user;
    }
}