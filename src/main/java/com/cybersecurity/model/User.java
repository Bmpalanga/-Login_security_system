package com.cybersecurity.model;

public class User {

    private int id;
    private String username;
    private String passwordHash;
    private int failedAttempts;
    private boolean locked;

    public User(int id, String username, String passwordHash) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.failedAttempts = 0;
        this.locked = false;
    }

    public User(
            int id,
            String username,
            String passwordHash,
            int failedAttempts,
            boolean locked
    ) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.failedAttempts = failedAttempts;
        this.locked = locked;
    }

    public int getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public boolean isLocked() {
        return locked;
    }

    public void incrementFailedAttempts() {
        failedAttempts++;
    }

    public void resetFailedAttempts() {
        failedAttempts = 0;
    }

    public void lockAccount() {
        locked = true;
    }
}