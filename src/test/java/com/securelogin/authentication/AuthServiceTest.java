package com.securelogin.authentication;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**Each test gets its own isolated in-memory database, created fresh
 * in setUp() and discarded in tearDown(), so tests never see each other's data.
 */
class AuthServiceTest {

    private UserDatabase database;
    private AuthService authService;

    @BeforeEach
    void setUp() throws SQLException {
        String uniqueDbName = "testdb_" + UUID.randomUUID().toString().replace("-", "");
        database = new UserDatabase("jdbc:h2:mem:" + uniqueDbName);
        database.initSchema();
        authService = new AuthService(database);
    }

    @AfterEach
    void tearDown() throws SQLException {
        database.close();
    }

    @Test
    @DisplayName("TC-01: registering with valid credentials succeeds")
    void registerWithValidCredentialsSucceeds() {
        AuthService.Result result = authService.register("alice.jones", "SafePassw0rd!".toCharArray());

        assertTrue(result.success());
        assertEquals("Account 'alice.jones' created.", result.message());
    }

    @Test
    @DisplayName("TC-02: registering a duplicate username fails")
    void registerDuplicateUsernameFails() {
        authService.register("alice.jones", "SafePassw0rd!".toCharArray());

        AuthService.Result result = authService.register("alice.jones", "AnotherPass1!".toCharArray());

        assertFalse(result.success());
        assertEquals("That username is already taken.", result.message());
    }

    @Test
    @DisplayName("TC-03: registering with a short password fails validation")
    void registerShortPasswordFails() {
        AuthService.Result result = authService.register("newuser1", "short1".toCharArray());

        assertFalse(result.success());
        assertTrue(result.message().contains("at least 10 characters"));
    }

    @Test
    @DisplayName("TC-04: registering with an invalid username format fails validation")
    void registerInvalidUsernameFormatFails() {
        AuthService.Result result = authService.register("bad user!", "ValidPass1!".toCharArray());

        assertFalse(result.success());
        assertTrue(result.message().contains("3-32 characters"));
    }

    @Test
    @DisplayName("TC-05: registering with a too-short username fails validation")
    void registerTooShortUsernameFails() {
        AuthService.Result result = authService.register("zi", "ValidPass1!".toCharArray());

        assertFalse(result.success());
        assertTrue(result.message().contains("3-32 characters"));
    }

    @Test
    @DisplayName("TC-06: logging in with correct credentials succeeds")
    void loginWithCorrectCredentialsSucceeds() {
        authService.register("alice.jones", "SafePassw0rd!".toCharArray());

        AuthService.Result result = authService.login("alice.jones", "SafePassw0rd!".toCharArray());

        assertTrue(result.success());
        assertEquals("Welcome back, alice.jones.", result.message());
    }

    @Test
    @DisplayName("TC-07: logging in with the wrong password fails")
    void loginWithWrongPasswordFails() {
        authService.register("alice.jones", "SafePassw0rd!".toCharArray());

        AuthService.Result result = authService.login("alice.jones", "WrongPass1!".toCharArray());

        assertFalse(result.success());
        assertEquals("Invalid username or password.", result.message());
    }

    @Test
    @DisplayName("TC-08: logging in with an unknown username fails with the same message as a wrong password")
    void loginWithUnknownUsernameFailsWithSameMessageAsWrongPassword() {
        authService.register("bob.smith", "SafePassw0rd!".toCharArray());
        AuthService.Result wrongPasswordResult = authService.login("bob.smith", "WrongPass1!".toCharArray());

        AuthService.Result unknownUserResult = authService.login("nobody99", "AnyPass1!".toCharArray());

        assertFalse(unknownUserResult.success());
        assertEquals(wrongPasswordResult.message(), unknownUserResult.message());
    }

    @Test
    @DisplayName("TC-10: account locks after 5 consecutive failed logins")
    void accountLocksAfterFiveFailedAttempts() {
        authService.register("alice.jones", "SafePassw0rd!".toCharArray());

        for (int attempt = 1; attempt <= 5; attempt++) {
            authService.login("alice.jones", "WrongPass1!".toCharArray());
        }

        AuthService.Result result = authService.login("alice.jones", "WrongPass1!".toCharArray());

        assertFalse(result.success());
        assertTrue(result.message().startsWith("Too many failed attempts"));
    }

    @Test
    @DisplayName("TC-11: a locked account rejects the correct password too")
    void lockedAccountRejectsCorrectPassword() {
        authService.register("alice.jones", "SafePassw0rd!".toCharArray());
        for (int attempt = 1; attempt <= 5; attempt++) {
            authService.login("alice.jones", "WrongPass1!".toCharArray());
        }

        AuthService.Result result = authService.login("alice.jones", "SafePassw0rd!".toCharArray());

        assertFalse(result.success());
        assertTrue(result.message().startsWith("Too many failed attempts"));
    }
}