package com.cybersecurity.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseManager {

    private static String databaseUrl =
            "jdbc:sqlite:login_security.db";

    public static Connection getConnection()
            throws SQLException {

        return DriverManager.getConnection(databaseUrl);
    }

    public static void setDatabaseUrl(String url) {
        databaseUrl = url;
    }

    public static void resetDatabaseUrl() {
        databaseUrl =
                "jdbc:sqlite:login_security.db";
    }
}