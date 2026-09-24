package com.securelogin.authentication;

import java.security.SecureRandom;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

public final class AuthService {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.]{3,32}$");
    private static final int MIN_PASSWORD_LENGTH = 10;

    // Dummy values so a login check for an unknown username still runs the full hash
    // comparison. Otherwise "no such user" would return faster than "wrong password",
    // and that timing difference is enough for someone to figure out which usernames exist.
    private static final byte[] DUMMY_SALT = new byte[16];
    private static final byte[] DUMMY_HASH;

    static {
        new SecureRandom().nextBytes(DUMMY_SALT);
        DUMMY_HASH = new PasswordHasher().hash("not-a-real-account-password".toCharArray()).hash();
    }

    public record Result(boolean success, String message) {
        static Result ok(String message) {
            return new Result(true, message);
        }

        static Result fail(String message) {
            return new Result(false, message);
        }
    }

    private final UserDatabase database;
    private final PasswordHasher hasher = new PasswordHasher();
    private final LoginAttemptTracker attemptTracker = new LoginAttemptTracker();

    public AuthService(UserDatabase database) {
        this.database = database;
    }

    public Result register(String username, char[] password) {
        List<String> errors = validate(username, password);
        if (!errors.isEmpty()) {
            return Result.fail(String.join("; ", errors));
        }
        try {
            if (database.usernameExists(username)) {
                return Result.fail("That username is already taken.");
            }
            PasswordHasher.Hashed hashed = hasher.hash(password);
            database.insert(new UserAccount(UUID.randomUUID(), username, hashed.hash(), hashed.salt(), Instant.now()));
            return Result.ok("Account '" + username + "' created.");
        } catch (SQLException e) {
            return Result.fail("Registration failed: " + e.getMessage());
        }
    }

}
