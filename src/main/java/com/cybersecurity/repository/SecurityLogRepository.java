package com.cybersecurity.repository;

import com.cybersecurity.database.DatabaseManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class SecurityLogRepository {

    public void saveLog(String username, String event) {

        String sql = """
                INSERT INTO security_logs
                (username, event, timestamp)
                VALUES (?, ?, datetime('now'))
                """;

        try (Connection connection = DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(1, username);
            statement.setString(2, event);

            statement.executeUpdate();

        } catch (SQLException e) {
            System.out.println("Could not save security log.");
            e.printStackTrace();
        }
    }

    public List<String> findLogsByUsername(String username) {

        List<String> logs = new ArrayList<>();

        String sql = """
                SELECT event, timestamp
                FROM security_logs
                WHERE username = ?
                ORDER BY id
                """;

        try (Connection connection = DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(1, username);

            ResultSet resultSet = statement.executeQuery();

            while (resultSet.next()) {

                String event = resultSet.getString("event");
                String timestamp = resultSet.getString("timestamp");

                logs.add(timestamp + " - " + event);
            }

        } catch (SQLException e) {
            System.out.println("Could not retrieve security logs.");
            e.printStackTrace();
        }

        return logs;
    }
}