
package com.cybersecurity.repository;

import com.cybersecurity.database.DatabaseManager;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class SecurityLogRepository {

    // Existing method used by AuthService.
    // If no IP address is provided, store UNKNOWN.
    public void saveLog(String username, String event) {

        saveLog(username, event, "UNKNOWN");
    }

    // New method that allows us to store an IP address.
    public void saveLog(
            String username,
            String event,
            String ipAddress
    ) {

        String sql = """
                INSERT INTO security_logs
                (username, event, ip_address, timestamp)
                VALUES (?, ?, ?, datetime('now'))
                """;

        try (Connection connection =
                     DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(1, username);
            statement.setString(2, event);
            statement.setString(3, ipAddress);

            statement.executeUpdate();

        } catch (SQLException e) {

            System.out.println(
                    "Could not save security log."
            );

            e.printStackTrace();
        }
    }

    // Retrieves security logs for a specific username.
    // The IP address is now included in the returned log.
    public List<String> findLogsByUsername(String username) {

        List<String> logs = new ArrayList<>();

        String sql = """
                SELECT event, timestamp, ip_address
                FROM security_logs
                WHERE username = ?
                ORDER BY id
                """;

        try (Connection connection =
                     DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(1, username);

            ResultSet resultSet =
                    statement.executeQuery();

            while (resultSet.next()) {

                String event =
                        resultSet.getString("event");

                String timestamp =
                        resultSet.getString("timestamp");

                String ipAddress =
                        resultSet.getString("ip_address");

                logs.add(
                        timestamp
                                + " - "
                                + event
                                + " - IP: "
                                + ipAddress
                );
            }

        } catch (SQLException e) {

            System.out.println(
                    "Could not retrieve security logs."
            );

            e.printStackTrace();
        }

        return logs;
    }

    // Deletes all security logs.
    public void deleteAll() {

        String sql =
                "DELETE FROM security_logs";

        try (Connection connection =
                     DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.executeUpdate();

        } catch (SQLException e) {

            System.out.println(
                    "Could not delete security logs."
            );

            e.printStackTrace();
        }
    }
}

