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

}
