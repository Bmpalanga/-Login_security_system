package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.repository.SecurityLogRepository;
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

        securityLogRepository =
                new SecurityLogRepository();
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
}