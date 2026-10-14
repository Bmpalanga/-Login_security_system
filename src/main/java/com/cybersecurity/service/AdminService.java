package com.cybersecurity.service;

import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;

import java.util.List;
import java.util.Optional;

public class AdminService {

    private final UserRepository userRepository;
    private final SecurityAuditService securityAuditService;

    public AdminService() {
        this.userRepository = new UserRepository();
        this.securityAuditService =
                new SecurityAuditService();
    }

    public Optional<User> findUser(String username) {

        return userRepository.findByUsername(username);
    }

    public void unlockUser(String username) {

        userRepository.unlockUser(username);
    }


    public List<String> getSecurityLogs(String username) {
        return securityAuditService.getUserAuditLogs(username);

    }

    public int countSuccessfulLogins(String username) {

        return securityAuditService
                .countSuccessfulLogins(username);
    }

    public int countFailedLogins(String username) {

        return securityAuditService
                .countFailedLogins(username);
    }

    public int countAccountLocks(String username) {

        return securityAuditService
                .countAccountLocks(username);
    }

    public int countAutomaticUnlocks(String username) {

        return securityAuditService
                .countAutomaticUnlocks(username);
    }

    public int countRateLimitedAttempts(String username) {

        return securityAuditService
                .countRateLimitedAttempts(username);
    }


}