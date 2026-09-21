package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

public class UserRepositoryTest {

    private UserRepository userRepository;

    @BeforeEach
    void setUp() {

        DatabaseManager.setDatabaseUrl(
                "jdbc:sqlite:login_security_test.db"
        );

        DatabaseInitializer.initializeDatabase();

        userRepository = new UserRepository();

        userRepository.deleteAll();
    }

    @Test
    void shouldFindUserByUsername() {

        User user = new User(
                1,
                "testUser",
                "hashedPassword"
        );

        userRepository.save(user);

        Optional<User> foundUser =
                userRepository.findByUsername("testUser");

        assertTrue(foundUser.isPresent());

        assertEquals(
                "testUser",
                foundUser.get().getUsername()
        );
    }
}