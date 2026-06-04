package com.audit.pki.config;

import org.junit.jupiter.api.Test;

import com.audit.pki.config.Database;

import java.sql.Connection;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseConnectionTest {

    @Test
    void testDatabaseConnectionIsValid() throws SQLException {
        // Act: Attempt to get the connection
        Connection connection = Database.getInstance().getConnection();

        // Assert: Verify it is not null
        assertNotNull(connection, "Connection should not be null");

        // Assert: Verify the connection is actually alive (timeout of 2 seconds)
        assertTrue(connection.isValid(2), "Database connection should be valid and open");
    }
}