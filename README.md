 **Security Login CLI**

WTC-DP34BF8P

**ABOUT:** 

This is an interactive Java CLI for registering and logging in users, built to
demonstrate core cybersecurity fundamentals rather than any particular framework.

**THE PROBLEM IT ADDRESSES:**

Login systems break in a few well-known, avoidable ways: storing passwords in
plaintext, building SQL queries by string concatenation, and allowing unlimited login
attempts. This project applies the standard fixes for all three in a small codebase.

**BUILD & RUN:**
**build a runnable jar:**

1.mvn package
2.java -jar target/secure-login-cli.jar

-Commands once running: register, login, exit.

The H2 database file is created automatically at `./data/login.mv.db` on first run.

**WHERE EACH CYBERSECURITY FUNDAMENTAL LIVES:**

| Concern | Where | What it prevents |
|---|---|---|
| Password hashing | `core/PasswordHasher.java` — PBKDF2WithHmacSHA256, 600,000 iterations, random 16-byte salt per user | Stolen database rows don't hand over plaintext passwords |
| Constant-time comparison | `PasswordHasher.verify` uses `MessageDigest.isEqual` | Prevents timing attacks that could reveal how much of a guessed hash matched |
| Parameterized queries | `core/UserDatabase.java` — every query is a `PreparedStatement` with `?` placeholders | SQL injection via username/password input |
| Input validation | `core/AuthService.validate` — username format/length, minimum password length | Malformed or empty input reaching the database or hasher |
| Brute-force lockout | `core/LoginAttemptTracker.java` — locks an account for 60s after 5 failed attempts | Unlimited automated password guessing |
| Username enumeration & timing protection | `AuthService.login` runs the full-cost hash check even for a username that doesn't exist, and returns the same "Invalid username or password" message either way | An attacker learning which usernames are registered from response time or wording |

**TESTING:**

See `TEST_PLAN.md` for the full set of manual test cases (registration, login,
duplicate usernames, weak passwords, lockout behaviour) plus how to run the automated
tests with `mvn test`.

**WHAT IS DELIBERATELY LEFT OUT:**

- No encryption of stored data — passwords are *hashed* (one-way, for verification
  only), not encrypted, which is the correct primitive for a login system.
- No web layer, sessions, or tokens — this is a command-line proof of the security
  fundamentals, not a full auth system.
- Targets Java 21 so it runs unchanged on 21 through 26+ without any special flags.


