package com.audit.pki.repos;

import org.junit.jupiter.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.audit.pki.repos.interfaces.CertificateRepoInterface;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.config.Database;
import com.audit.pki.models.Certificate;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

class CertificateRepositoryTest {

    private CertificateRepoInterface certificateRepository;

    @BeforeEach
    void setUp() {
        Database db = Database.getInstance();
        certificateRepository = new CertificateRepository(db);
    }

    @Test
    void testSaveCertificate() throws Exception {

        Certificate testCert = new Certificate(
                "1234567890ABCDEF",
                "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2",
                "CN=test.example.com, O=Audit Corp, C=SE",
                "CN=Example Root CA, O=Example Trust, C=US",
                List.of("test.example.com", "www.test.example.com"),
                Instant.now(),
                Instant.now().plus(365, java.time.temporal.ChronoUnit.DAYS),
                "SHA256withRSA",
                "RSA",
                2048,
                List.of("serverAuth", "clientAuth"),
                "-----BEGIN CERTIFICATE-----\nMIID...[test_raw_base64]...\n-----END CERTIFICATE-----");

        // Act
        certificateRepository.saveCertificate(testCert);

        // Assert - Verify via raw JDBC since findById() doesn't exist yet
        Connection conn = Database.getInstance().getConnection();
        String sql = "SELECT COUNT(*) FROM certificates WHERE id = ?";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            // Passing the UUID directly; the JDBC driver handles the Postgres UUID mapping
            stmt.setObject(1, testCert.getId());
            ResultSet rs = stmt.executeQuery();

            assertTrue(rs.next(), "Result set should not be empty");
            assertEquals(1, rs.getInt(1), "Exactly one row should exist with the given UUID");
        }
    }
}
