package com.securelogin.authentication;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHasherTest {

    @Test
    void correctPasswordVerifiesAgainstItsOwnHash() {
        PasswordHasher hasher = new PasswordHasher();
        PasswordHasher.Hashed hashed = hasher.hash("correct-horse-battery".toCharArray());

        assertTrue(hasher.verify("correct-horse-battery".toCharArray(), hashed.hash(), hashed.salt()));
    }

    @Test
    void wrongPasswordFailsVerification() {
        PasswordHasher hasher = new PasswordHasher();
        PasswordHasher.Hashed hashed = hasher.hash("correct-horse-battery".toCharArray());

        assertFalse(hasher.verify("wrong-password".toCharArray(), hashed.hash(), hashed.salt()));
    }

    @Test
    void sameSaltDifferentPasswordsProduceDifferentHashes() {
        PasswordHasher hasher = new PasswordHasher();
        PasswordHasher.Hashed a = hasher.hash("password-one".toCharArray());
        PasswordHasher.Hashed b = hasher.hash("password-two".toCharArray());

        assertFalse(java.security.MessageDigest.isEqual(a.hash(), b.hash()));
    }
}
