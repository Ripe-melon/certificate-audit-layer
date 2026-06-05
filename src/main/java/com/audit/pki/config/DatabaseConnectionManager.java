package com.audit.pki.config;

import com.audit.pki.config.interfaces.Database;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConnectionManager implements Database {

    // State now only holds the credentials, not the active connection
    private final String url;
    private final String user;
    private final String password;

    public DatabaseConnectionManager(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
    }

    @Override
    public Connection getConnection() {
        try {
            return DriverManager.getConnection(url, user, password);
        } catch (SQLException e) {
            throw new RuntimeException("Failed to establish database connection.", e);
        }
    }
}