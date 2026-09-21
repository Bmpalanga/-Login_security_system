package com.cybersecurity.service;

import com.cybersecurity.model.User;
import com.cybersecurity.repository.SecurityLogRepository;
import com.cybersecurity.repository.UserRepository;

import java.util.List;
import java.util.Optional;

public class AdminService {

    private final UserRepository userRepository;
    private final SecurityLogRepository securityLogRepository;

    public AdminService() {
        this.userRepository = new UserRepository();
        this.securityLogRepository = new SecurityLogRepository();
    }

    public Optional<User> findUser(String username) {

        return userRepository.findByUsername(username);
    }

    public List<String> getSecurityLogs(String username) {

        return securityLogRepository.findLogsByUsername(username);
    }
}