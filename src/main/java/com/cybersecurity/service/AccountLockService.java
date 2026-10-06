
package com.cybersecurity.service;

import com.cybersecurity.model.User;
import com.cybersecurity.repository.UserRepository;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class AccountLockService {

    private static final long LOCK_DURATION_MINUTES = 15;

    private final UserRepository userRepository;

    public AccountLockService() {
        this.userRepository = new UserRepository();
    }

    public boolean shouldUnlock(User user) {

        if (!user.isLocked()) {
            return false;
        }

        if (user.getLockedAt() == null) {
            return false;
        }

        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern(
                        "yyyy-MM-dd HH:mm:ss"
                );

        LocalDateTime lockedAt =
                LocalDateTime.parse(
                        user.getLockedAt(),
                        formatter
                );

        LocalDateTime now =
                LocalDateTime.now();

        long minutesLocked =
                Duration.between(
                        lockedAt,
                        now
                ).toMinutes();

        return minutesLocked >= LOCK_DURATION_MINUTES;
    }

    public boolean unlockIfExpired(User user) {

        if (!shouldUnlock(user)) {
            return false;
        }

        user.unlockAccount();

        userRepository.updateSecurityStatus(user);

        return true;
    }
}

