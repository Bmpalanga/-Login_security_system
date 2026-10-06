
package com.cybersecurity.database;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseInitializer {

    public static void initializeDatabase() {

        String usersSql = """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked INTEGER NOT NULL DEFAULT 0,
                    locked_at TEXT,
                    created_at TEXT NOT NULL
                )
                """;

        String logsSql = """
                CREATE TABLE IF NOT EXISTS security_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    event TEXT NOT NULL,
                    ip_address TEXT NOT NULL DEFAULT 'UNKNOWN',
                    timestamp TEXT NOT NULL
                )
                """;

        try (Connection connection =
                     DatabaseManager.getConnection();
             Statement statement =
                     connection.createStatement()) {

            /*
             * Create the users table if it does not exist.
             */
            statement.execute(usersSql);

            /*
             * Create the security logs table if it does not exist.
             */
            statement.execute(logsSql);

            /*
             * Add locked_at to an existing users table.
             *
             * If the column already exists, the ALTER TABLE
             * statement will fail and the exception is ignored.
             */
            try {

                statement.execute("""
                        ALTER TABLE users
                        ADD COLUMN locked_at TEXT
                        """);

            } catch (SQLException ignored) {
                // Column already exists.
            }

            /*
             * Add ip_address to an older security_logs table.
             *
             * This keeps existing development databases
             * compatible with the new schema.
             */
            try {

                statement.execute("""
                        ALTER TABLE security_logs
                        ADD COLUMN ip_address TEXT NOT NULL
                        DEFAULT 'UNKNOWN'
                        """);

            } catch (SQLException ignored) {
                // Column already exists.
            }

            System.out.println(
                    "Database initialized successfully."
            );

        } catch (SQLException e) {

            System.out.println(
                    "Database initialization failed."
            );

            e.printStackTrace();
        }
    }
}

