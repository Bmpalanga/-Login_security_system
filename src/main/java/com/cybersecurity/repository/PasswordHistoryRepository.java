
package com.cybersecurity.repository;

import com.cybersecurity.database.DatabaseManager;
import org.mindrot.jbcrypt.BCrypt;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class PasswordHistoryRepository {

    public void savePassword(
            String username,
            String passwordHash
    ) {

        String sql = """
                INSERT INTO password_history
                (username, password_hash, created_at)
                VALUES (?, ?, datetime('now'))
                """;

        try (Connection connection =
                     DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(1, username);
            statement.setString(2, passwordHash);

            statement.executeUpdate();

        } catch (SQLException e) {

            System.out.println(
                    "Could not save password history."
            );

            e.printStackTrace();
        }
    }

    public boolean hasUsedPassword(
            String username,
            String password
    ) {

        String sql = """
                SELECT password_hash
                FROM password_history
                WHERE username = ?
                """;

        try (Connection connection =
                     DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.setString(1, username);

            ResultSet resultSet =
                    statement.executeQuery();

            while (resultSet.next()) {

                String passwordHash =
                        resultSet.getString("password_hash");

                if (BCrypt.checkpw(
                        password,
                        passwordHash
                )) {

                    return true;
                }
            }

        } catch (SQLException e) {

            System.out.println(
                    "Could not check password history."
            );

            e.printStackTrace();
        }

        return false;
    }

    public void deleteAll() {

        String sql =
                "DELETE FROM password_history";

        try (Connection connection =
                     DatabaseManager.getConnection();
             PreparedStatement statement =
                     connection.prepareStatement(sql)) {

            statement.executeUpdate();

        } catch (SQLException e) {

            System.out.println(
                    "Could not delete password history."
            );

            e.printStackTrace();
        }
    }
}

