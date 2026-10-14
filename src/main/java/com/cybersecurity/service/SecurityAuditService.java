
package com.cybersecurity.service;

import com.cybersecurity.repository.SecurityLogRepository;

import java.util.List;

public class SecurityAuditService {

    private final SecurityLogRepository securityLogRepository;

    public SecurityAuditService() {

        this.securityLogRepository =
                new SecurityLogRepository();
    }

    public List<String> getUserAuditLogs(String username) {

        return securityLogRepository
                .findLogsByUsername(username);
    }

    public boolean hasSecurityEvents(String username) {

        return !getUserAuditLogs(username).isEmpty();
    }

    public int countEvents(
            String username,
            String event
    ) {

        List<String> logs =
                getUserAuditLogs(username);

        int count = 0;

        for (String log : logs) {

            if (log.contains(event)) {
                count++;
            }
        }

        return count;
    }

    public int countSuccessfulLogins(
            String username
    ) {

        return countEvents(
                username,
                "LOGIN_SUCCESS"
        );
    }

    public int countFailedLogins(
            String username
    ) {

        return countEvents(
                username,
                "LOGIN_FAILED"
        );
    }

    public int countAccountLocks(
            String username
    ) {

        return countEvents(
                username,
                "ACCOUNT_LOCKED"
        );
    }

    public int countAutomaticUnlocks(
            String username
    ) {

        return countEvents(
                username,
                "ACCOUNT_AUTO_UNLOCKED"
        );
    }

    public int countRateLimitedAttempts(
            String username
    ) {

        return countEvents(
                username,
                "LOGIN_RATE_LIMITED"
        );
    }
}

