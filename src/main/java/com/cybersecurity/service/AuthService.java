package com.cybersecurity.service;

import com.cybersecurity.model.User;

public class AuthService {

    private final PasswordService passwordService;

    public AuthService() {
        this.passwordService = new PasswordService();
    }

    public User registerUser(int id, String username, String password) {

        String passwordHash = passwordService.hashPassword(password);

        return new User(
                id,
                username,
                passwordHash
        );
    }
}