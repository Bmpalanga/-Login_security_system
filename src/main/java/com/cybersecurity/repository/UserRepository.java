package com.cybersecurity.repository;

import com.cybersecurity.database.DatabaseManager;
import com.cybersecurity.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.Optional;

public class UserRepository {

    public void save(User user) {

        String sql = """
                INSERT INTO users
                (id, username, password_hash, failed_attempts, locked, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """;

        try (Connection connection = DatabaseManager.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setInt(1, user.getId());
            statement.setString(2, user.getUsername());
            statement.setString(3, user.getPasswordHash());
            statement.setInt(4, user.getFailedAttempts());
            statement.setInt(5, user.isLocked() ? 1 : 0);
            statement.setString(6, LocalDateTime.now().toString());

            statement.executeUpdate();

            System.out.println("User saved successfully.");

        } catch (SQLException e) {
            System.out.println("Could not save user.");
            e.printStackTrace();
        }
    }

    public Optional<User> findByUsername(String username) {

        String sql = """
                SELECT id, username, password_hash,
                       failed_attempts, locked
                FROM users
                WHERE username = ?
                """;

        try (Connection connection = DatabaseManager.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, username);

            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {

                User user = new User(
                        resultSet.getInt("id"),
                        resultSet.getString("username"),
                        resultSet.getString("password_hash")
                );

                return Optional.of(user);
            }

        } catch (SQLException e) {
            System.out.println("Could not find user.");
            e.printStackTrace();
        }

        return Optional.empty();
    }
}