package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
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
        DatabaseInitializer.initializeDatabase();
        userRepository = new UserRepository();
    }

    @Test
    void shouldFindUserByUsername() {

        User user = new User(
                200,
                "repositoryUser",
                "hashedPassword"
        );

        userRepository.save(user);

        Optional<User> result =
                userRepository.findByUsername("repositoryUser");

        assertTrue(result.isPresent());

        assertEquals(
                "repositoryUser",
                result.get().getUsername()
        );
    }
}