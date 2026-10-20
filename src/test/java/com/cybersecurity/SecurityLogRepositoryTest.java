package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.repository.SecurityLogRepository;
import com.cybersecurity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SecurityLogRepositoryTest {

    private SecurityLogRepository securityLogRepository;

    @BeforeEach
    void setUp() {

        DatabaseManager.setDatabaseUrl(
                "jdbc:sqlite:login_security_test.db"
        );

        DatabaseInitializer.initializeDatabase();

        UserRepository userRepository =
                new UserRepository();

        userRepository.deleteAll();

        securityLogRepository =
                new SecurityLogRepository();

        securityLogRepository.deleteAll();
    }

    @Test
    void shouldFindLogsForUsername() {

        securityLogRepository.saveLog(
                "testUser",
                "LOGIN_SUCCESS"
        );

        List<String> logs =
                securityLogRepository.findLogsByUsername(
                        "testUser"
                );

        assertEquals(1, logs.size());

        assertTrue(
                logs.get(0).contains("LOGIN_SUCCESS")
        );
    }
    @Test
    void shouldSaveAndRetrieveIpAddress() {

        securityLogRepository.saveLog(
                "ipTestUser",
                "LOGIN_SUCCESS",
                "192.168.1.10"
        );

        List<String> logs =
                securityLogRepository.findLogsByUsername(
                        "ipTestUser"
                );

        assertEquals(1, logs.size());

        assertTrue(
                logs.get(0).contains("LOGIN_SUCCESS")
        );

        assertTrue(
                logs.get(0).contains("192.168.1.10"),
                "The security log should contain the IP address."
        );
    }
}