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

    public Result login(String username, char[] password) {
        if (attemptTracker.isLocked(username)) {
            return Result.fail("Too many failed attempts. Try again in "
                    + attemptTracker.secondsUntilUnlocked(username) + "s.");
        }
        try {
            Optional<UserAccount> account = database.findByUsername(username);

            byte[] hashToCheck = account.map(UserAccount::passwordHash).orElse(DUMMY_HASH);
            byte[] saltToUse = account.map(UserAccount::salt).orElse(DUMMY_SALT);
            boolean passwordMatches = hasher.verify(password, hashToCheck, saltToUse);
            boolean valid = account.isPresent() && passwordMatches;

            if (valid) {
                attemptTracker.recordSuccess(username);
                return Result.ok("Welcome back, " + username + ".");
            }
            attemptTracker.recordFailure(username);
            return Result.fail("Invalid username or password.");
        } catch (SQLException e) {
            return Result.fail("Login failed: " + e.getMessage());
        }
    }

    private List<String> validate(String username, char[] password) {
        List<String> errors = new ArrayList<>();
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            errors.add("Username must be 3-32 characters: letters, numbers, '.' or '_' only.");
        }
        if (password == null || password.length < MIN_PASSWORD_LENGTH) {
            errors.add("Password must be at least " + MIN_PASSWORD_LENGTH + " characters.");
        }
        return errors;
    }
}
