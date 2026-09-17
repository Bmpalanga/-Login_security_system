package com.cybersecurity.model;
import java.time.LocalDateTime;

public class User {

    private int id;
    private String username;
    private String passwordHash;
    private int failedAttempts;
    private boolean locked;
    private LocalDateTime createdAt;

    public User(int id, String username, String passwordHash) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.failedAttempts = 0;
        this.locked = false;
        this.createdAt = LocalDateTime.now();
    }

    public String getUsername() {
        return username;
    }

    public boolean isLocked() {
        return locked;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }
}