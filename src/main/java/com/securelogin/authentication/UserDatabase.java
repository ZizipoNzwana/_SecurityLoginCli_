package com.securelogin.authentication;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Optional;
import java.util.UUID;

// All queries use PreparedStatement placeholders -- a username is always bound as a
// parameter, never concatenated into the SQL text, so there's no SQL injection surface
// here regardless of what gets typed into the username or password fields.
public final class UserDatabase implements AutoCloseable {

    private final Connection connection;

    public UserDatabase(String jdbcUrl) throws SQLException {
        this.connection = DriverManager.getConnection(jdbcUrl, "login_admin", "");
    }

    public void initSchema() throws SQLException {
        String ddl = """
                CREATE TABLE IF NOT EXISTS app_user (
                    id            UUID PRIMARY KEY,
                    username      VARCHAR(32) NOT NULL UNIQUE,
                    password_hash VARBINARY(64) NOT NULL,
                    salt          VARBINARY(16) NOT NULL,
                    created_at    TIMESTAMP NOT NULL
                )
                """;
        try (Statement statement = connection.createStatement()) {
            statement.execute(ddl);
        }
    }

    public boolean usernameExists(String username) throws SQLException {
        String sql = "SELECT 1 FROM app_user WHERE username = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username);
            try (ResultSet rs = statement.executeQuery()) {
                return rs.next();
            }
        }
    }

    public void insert(UserAccount account) throws SQLException {
        String sql = """
                INSERT INTO app_user (id, username, password_hash, salt, created_at)
                VALUES (?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, account.id());
            statement.setString(2, account.username());
            statement.setBytes(3, account.passwordHash());
            statement.setBytes(4, account.salt());
            statement.setTimestamp(5, Timestamp.from(account.createdAt()));
            statement.executeUpdate();
        }
    }

    public Optional<UserAccount> findByUsername(String username) throws SQLException {
        String sql = "SELECT id, username, password_hash, salt, created_at FROM app_user WHERE username = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, username);
            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new UserAccount(
                        (UUID) rs.getObject("id"),
                        rs.getString("username"),
                        rs.getBytes("password_hash"),
                        rs.getBytes("salt"),
                        rs.getTimestamp("created_at").toInstant()));
            }
        }
    }

    @Override
    public void close() throws SQLException {
        connection.close();
    }
}
