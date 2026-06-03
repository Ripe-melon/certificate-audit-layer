package com.audit.pki.repos;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Singleton class to manage database connections.
 * Ensures only one connection instance is used throughout the application.
 */
public class DatabaseConnection {

    // Hardcoded for development. In production, these pull from environment
    // variables.
    private static final String URL = "jdbc:postgresql://localhost:5432/pki_audit";
    private static final String USER = "audit_admin";
    private static final String PASSWORD = "secure_password";

    private static DatabaseConnection instance;
    private Connection connection;

    // Private constructor prevents instantiation from outside
    private DatabaseConnection() {
        try {
            this.connection = DriverManager.getConnection(URL, USER, PASSWORD);
        } catch (SQLException e) {
            throw new RuntimeException("Failed to establish database connection.", e);
        }
    }

    public static synchronized DatabaseConnection getInstance() {
        if (instance == null) {
            instance = new DatabaseConnection();
        } else {
            try {
                if (instance.getConnection().isClosed()) {
                    instance = new DatabaseConnection();
                }
            } catch (SQLException e) {
                throw new RuntimeException("Error checking connection status.", e);
            }
        }
        return instance;
    }

    public Connection getConnection() {
        return connection;
    }
}