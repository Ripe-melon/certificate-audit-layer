package com.audit.pki.config;

import org.junit.jupiter.api.Test;
import java.sql.Connection;
import java.sql.SQLException;
import com.audit.pki.config.interfaces.Database;
import com.audit.pki.config.DatabaseConnectionManager;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseConnectionTest {

    @Test
    void testDatabaseConnectionIsValid() throws SQLException {
        // Arrange: Inject the exact credentials required for this specific test
        // environment
        Database dbManager = new DatabaseConnectionManager(
                "jdbc:postgresql://localhost:5432/pki_audit",
                "audit_admin",
                "secure_password");

        // Act: Request the connection
        Connection connection = dbManager.getConnection();

        // Assert: Verify the instance exists
        assertNotNull(connection, "Connection should not be null");

        // Assert: Verify the connection can successfully ping the PostgreSQL engine
        assertTrue(connection.isValid(2), "Database connection should be valid and open");
    }

}
