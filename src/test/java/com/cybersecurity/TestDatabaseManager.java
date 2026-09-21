package com.cybersecurity;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class TestDatabaseManager {

    private static final String URL =
            "jdbc:sqlite:login_security_test.db";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL);
    }
}