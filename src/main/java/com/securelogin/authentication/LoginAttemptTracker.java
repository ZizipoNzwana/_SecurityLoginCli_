package com.securelogin.authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;

// Locks a username out for a short window after too many failed logins in a row,
// so a script can't just sit there guessing passwords forever.
public final class LoginAttemptTracker {

    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_SECONDS = 60;

    private record State(int failedAttempts, Instant lockedUntil) {
    }

    private final ConcurrentHashMap<String, State> attempts = new ConcurrentHashMap<>();

    public boolean isLocked(String username) {
        State state = attempts.get(username);
        return state != null && state.lockedUntil() != null && Instant.now().isBefore(state.lockedUntil());
    }

    public long secondsUntilUnlocked(String username) {
        State state = attempts.get(username);
        if (state == null || state.lockedUntil() == null) {
            return 0;
        }
        long remaining = Instant.now().until(state.lockedUntil(), ChronoUnit.SECONDS);
        return Math.max(remaining, 0);
    }

    public void recordFailure(String username) {
        attempts.compute(username, (name, current) -> {
            int failures = (current == null ? 0 : current.failedAttempts()) + 1;
            Instant lockUntil = failures >= MAX_ATTEMPTS ? Instant.now().plusSeconds(LOCKOUT_SECONDS) : null;
            return new State(failures, lockUntil);
        });
    }

    public void recordSuccess(String username) {
        attempts.remove(username);
    }
}
