package com.cybersecurity;

import com.cybersecurity.service.PasswordService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordServiceTest {

    @Test
    void passwordCanBeHashedAndVerified() {

        PasswordService passwordService = new PasswordService();

        String password = "MyPassword123";

        String hash = passwordService.hashPassword(password);

        assertNotEquals(password, hash);
        assertTrue(passwordService.verifyPassword(password, hash));
    }

    @Test
    void wrongPasswordShouldFail() {

        PasswordService passwordService = new PasswordService();

        String hash = passwordService.hashPassword("MyPassword123");

        assertFalse(
                passwordService.verifyPassword("WrongPassword", hash)
        );
    }
}