package com.securelogin.authentication;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * One-way password hashing using PBKDF2 with HMAC-SHA256, a random salt per user, and
 * an iteration count matching current OWASP guidance. Hashing is one-way on purpose --
 * a login only ever needs to check a password, never recover it.
 */
public final class PasswordHasher {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000; // OWASP-recommended floor for PBKDF2-HMAC-SHA256
    private static final int KEY_LENGTH_BITS = 256;
    private static final int SALT_LENGTH_BYTES = 16;

    private final SecureRandom secureRandom = new SecureRandom();

    public record Hashed(byte[] hash, byte[] salt) {
    }

    public Hashed hash(char[] password) {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);
        return new Hashed(pbkdf2(password, salt), salt);
    }

    // Uses MessageDigest.isEqual for a constant-time comparison, so a failed login
    // attempt can't be timed to learn how close the guess was.
    public boolean verify(char[] password, byte[] expectedHash, byte[] salt) {
        byte[] candidate = pbkdf2(password, salt);
        return MessageDigest.isEqual(candidate, expectedHash);
    }

    private byte[] pbkdf2(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Password hashing failed", e);
        } finally {
            spec.clearPassword();
        }
    }
}
