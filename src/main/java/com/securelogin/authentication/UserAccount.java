package com.securelogin.authentication;

import java.time.Instant;
import java.util.UUID;

public record UserAccount(UUID id, String username, byte[] passwordHash, byte[] salt, Instant createdAt) {
}
