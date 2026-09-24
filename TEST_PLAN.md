# Test Plan — Secure Login CLI

**1.Introduction**

This document specifies the testing approach for the Secure Login CLI, a command-line
application for user registration and login. The application's purpose is to
demonstrate core cybersecurity fundamentals — password hashing, safe database access,
input validation, and brute-force protection — so testing is weighted toward
confirming those specific behaviours, not just general functional correctness.

**2.Scope**

**In scope:**
- User registration (valid and invalid input)
- User login (valid and invalid credentials)
- Account lockout after repeated failed logins
- Password storage behaviour (hashing, not plaintext)
- Protection against revealing which usernames are registered

**Out of scope:**
- Performance/load testing
- Concurrent multi-user access
- Any web-based or networked interface (this build is command-line only)
- Penetration testing of the underlying H2 database engine itself

**3.Test Objectives**

1. Confirm registration and login behave correctly for valid input.
2. Confirm the system rejects invalid input with a clear, correct message.
3. Confirm passwords are never recoverable from stored data.
4. Confirm the system does not allow unlimited password guessing.
5. Confirm the system does not leak which usernames exist through wording or timing.

**4.Test Environment**

| Item | Detail |
|---|---|
| Language / runtime | Java 21+ (compiles and runs unchanged on 25/26) |
| Build tool | Maven 3.9+ |
| Database | Embedded H2 (file-based for manual testing, in-memory for automated tests) |
| Automated test framework | JUnit 5 (Jupiter) |
| Interface under test | Command-line (`register`, `login`, `exit`) |

**5.Test Strategy**

Two levels of testing are used:

- **Automated tests** exercise `AuthService` and `PasswordHasher` directly against an
  in-memory database, so they run in seconds and don't depend on typing into the
  terminal. These give fast, repeatable coverage of the core logic.
- **Manual tests** exercise the actual command-line program end to end, including
  cases that only show up when the program is really run — process restarts,
  message wording as the user actually sees it, and timing behaviour.

**6.Entry / Exit Criteria**

**Entry criteria:** the project compiles successfully (`mvn compile`) and the database
schema initializes without error on first run.

**Exit criteria:** all automated tests pass (`mvn test`), and every manual test case
below has been executed at least once with the actual result recorded.

** 7.Test Case Specifications**

| Test Case ID | Title | Test Steps | Expected Result |
|---|---|---|---|
| TC-01 | Register with valid credentials | 1. Call `register` with a valid username and password | Result is success; account is stored |
| TC-02 | Reject duplicate username | 1. Register a username 2. Call `register` again with the same username | Result is failure: "That username is already taken." |
| TC-03 | Reject password below minimum length | 1. Call `register` with a password under 10 characters | Result is failure with a password-length validation message |
| TC-04 | Reject invalid username format | 1. Call `register` with a username containing an invalid character | Result is failure with a username-format validation message |
| TC-05 | Reject username shorter than 3 characters | 1. Call `register` with a 2-character username | Result is failure with a username-format validation message |
| TC-06 | Login with correct credentials | 1. Register an account 2. Call `login` with the matching username and password | Result is success: "Welcome back, [username]." |
| TC-07 | Login with wrong password | 1. Register an account 2. Call `login` with the correct username, incorrect password | Result is failure: "Invalid username or password." |
| TC-08 | Login with a username that does not exist | 1. Call `login` with a username that was never registered | Result is failure with the **same message** as TC-07 |
| TC-09 | Passwords are not stored in plaintext | 1. Register an account 2. Open the H2 database file directly and inspect the stored row | The stored value is a fixed-length binary hash, not the original password text |
| TC-10 | Account locks after repeated failed logins | 1. Register an account 2. Call `login` with the wrong password 5 times in a row 3. Call `login` one more time (6th call, any credentials) | The 5th failed attempt still returns "Invalid username or password."; the 6th call returns a lockout message instead |
| TC-11 | Locked account rejects even the correct password | 1. Trigger a lockout (5 consecutive failed logins) 2. Immediately call `login` again with the correct password | Result is still failure with the lockout message |
| TC-12 | Successful login resets the failed-attempt count | 1. Register an account 2. Fail login 3 times 3. Log in successfully 4. Fail login once more | The single failure after the successful login does **not** trigger a lockout |
| TC-13 | Data persists after restarting the program | 1. Register an account 2. Exit the program 3. Restart the program 4. Log in with the same credentials | Login succeeds after restart, confirming data is read from disk, not held only in memory |
| TC-14 | Empty username on registration | 1. Call `register` and press Enter without typing a username | Result is failure with a username-format validation message |

**8.Traceability to Objectives**

| Objective | Covered by |
|---|---|
| Valid registration/login behaves correctly | TC-01, TC-06, TC-13 |
| Invalid input is rejected correctly | TC-02, TC-03, TC-04, TC-05, TC-14 |
| Passwords are never recoverable | TC-09 |
| No unlimited password guessing | TC-10, TC-11, TC-12 |
| Username existence is not leaked | TC-07, TC-08 |

**9.Deliverables:**

- `AuthServiceTest.java` — automated tests implementing TC-01 through TC-08, TC-10, and TC-11.
- `PasswordHasherTest.java` — supporting unit tests for the hashing logic itself (correct
  password verifies, wrong password fails, two different passwords never collide).
- Manual test results for TC-09, TC-12, TC-13, TC-14, recorded separately when executed.