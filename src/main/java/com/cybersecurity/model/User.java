package com.cybersecurity.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class User {

    private int id;
    private String username;
    private String passwordHash;
    private int failedAttempts;
    private boolean locked;
    private String lockedAt;

    public User(int id, String username, String passwordHash) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.failedAttempts = 0;
        this.locked = false;
        this.lockedAt = null;
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
        this.lockedAt = null;
    }

    public User(
            int id,
            String username,
            String passwordHash,
            int failedAttempts,
            boolean locked,
            String lockedAt
    ) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.failedAttempts = failedAttempts;
        this.locked = locked;
        this.lockedAt = lockedAt;
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

    public String getLockedAt() {
        return lockedAt;
    }

    public void incrementFailedAttempts() {
        failedAttempts++;
    }

    public void resetFailedAttempts() {
        failedAttempts = 0;
    }

    public void lockAccount() {

        locked = true;

        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern(
                        "yyyy-MM-dd HH:mm:ss"
                );

        lockedAt =
                LocalDateTime.now().format(formatter);
    }

    public void unlockAccount() {

        locked = false;
        failedAttempts = 0;
        lockedAt = null;
    }


}

