package com.cybersecurity;

import com.cybersecurity.model.User;
import com.cybersecurity.service.PasswordService;

public class Main {

    public static void main(String[] args) {

        PasswordService passwordService = new PasswordService();

        // User's original password
        String password = "MyPassword123";

        // Create the hash
        String passwordHash = passwordService.hashPassword(password);

        // Give the hash to User
        User user = new User(
                1,
                "babalwa",
                passwordHash
        );

        System.out.println("Username: " + user.getUsername());
        System.out.println("Stored password: " + user.getPasswordHash());
    }
}