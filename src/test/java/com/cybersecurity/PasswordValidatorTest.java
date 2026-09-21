package com.cybersecurity;

import com.cybersecurity.model.User;
import com.cybersecurity.service.AuthService;
import com.cybersecurity.service.PasswordValidator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class PasswordValidatorTest {

    private final PasswordValidator validator =
            new PasswordValidator();

    @Test
    void strongPasswordShouldBeAccepted() {

        assertTrue(
                validator.isStrong("Password123!")
        );
    }

    @Test
    void passwordWithoutUppercaseShouldBeRejected() {

        assertFalse(
                validator.isStrong("password123!")
        );
    }

    @Test
    void passwordWithoutLowercaseShouldBeRejected() {

        assertFalse(
                validator.isStrong("PASSWORD123!")
        );
    }

    @Test
    void passwordWithoutNumberShouldBeRejected() {

        assertFalse(
                validator.isStrong("Password!")
        );
    }

    @Test
    void passwordWithoutSpecialCharacterShouldBeRejected() {

        assertFalse(
                validator.isStrong("Password123")
        );
    }

    @Test
    void shortPasswordShouldBeRejected() {

        assertFalse(
                validator.isStrong("Pass1!")
        );
    }

    @Test
    void nullPasswordShouldBeRejected() {

        assertFalse(
                validator.isStrong(null)
        );
    }
    @Test
    void weakPasswordShouldBeRejectedDuringRegistration() {

        AuthService authService = new AuthService();

        assertThrows(
                IllegalArgumentException.class,
                () -> authService.registerUser(
                        600,
                        "weakUser",
                        "password"
                )
        );
    }
    @Test
    void strongPasswordShouldBeAcceptedDuringRegistration() {

        AuthService authService = new AuthService();

        User user = authService.registerUser(
                601,
                "strongUser",
                "Password123!"
        );

        assertNotNull(user);
        assertEquals("strongUser", user.getUsername());
    }
}