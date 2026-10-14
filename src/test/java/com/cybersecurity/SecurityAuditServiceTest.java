
package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.repository.SecurityLogRepository;
import com.cybersecurity.service.SecurityAuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SecurityAuditServiceTest {

    @BeforeEach
    void setUp() {

        DatabaseManager.setDatabaseUrl(
                "jdbc:sqlite:login_security_test.db"
        );

        DatabaseInitializer.initializeDatabase();

        SecurityLogRepository repository =
                new SecurityLogRepository();

        repository.deleteAll();
    }

    @Test
    void shouldRetrieveUserAuditLogs() {

        SecurityLogRepository repository =
                new SecurityLogRepository();

        repository.saveLog(
                "auditUser",
                "LOGIN_SUCCESS",
                "192.168.1.10"
        );

        repository.saveLog(
                "auditUser",
                "LOGIN_FAILED_WRONG_PASSWORD",
                "192.168.1.10"
        );

        SecurityAuditService auditService =
                new SecurityAuditService();

        List<String> logs =
                auditService.getUserAuditLogs(
                        "auditUser"
                );

        assertEquals(2, logs.size());

        assertTrue(
                logs.get(0).contains("LOGIN_SUCCESS")
        );

        assertTrue(
                logs.get(1).contains(
                        "LOGIN_FAILED_WRONG_PASSWORD"
                )
        );
    }

    @Test
    void shouldDetectSecurityEvents() {

        SecurityLogRepository repository =
                new SecurityLogRepository();

        repository.saveLog(
                "securityUser",
                "ACCOUNT_LOCKED",
                "192.168.1.20"
        );

        SecurityAuditService auditService =
                new SecurityAuditService();

        assertTrue(
                auditService.hasSecurityEvents(
                        "securityUser"
                )
        );
    }

    @Test
    void shouldReturnFalseWhenUserHasNoSecurityEvents() {

        SecurityAuditService auditService =
                new SecurityAuditService();

        assertFalse(
                auditService.hasSecurityEvents(
                        "userWithNoLogs"
                )
        );
    }
}


