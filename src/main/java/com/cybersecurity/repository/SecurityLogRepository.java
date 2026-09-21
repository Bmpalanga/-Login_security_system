package com.cybersecurity.repository;

import com.cybersecurity.database.DatabaseManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.LocalDateTime;

public class SecurityLogRepository {

    public void saveLog(String username, String event) {

        String sql = """
                INSERT INTO security_logs
                (username, event, timestamp)
                VALUES (?, ?, ?)
                """;

        try (Connection connection = DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(1, username);
            statement.setString(2, event);
            statement.setString(3, LocalDateTime.now().toString());

            statement.executeUpdate();

        } catch (SQLException e) {
            System.out.println("Could not save security log.");
            e.printStackTrace();
        }
    }
}