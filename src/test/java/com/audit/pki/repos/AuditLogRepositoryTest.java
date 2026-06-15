package com.audit.pki.repos;

import com.google.gson.JsonParser;
import com.audit.pki.config.DatabaseConnectionManager;
import com.audit.pki.models.AuditLog;
import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.AuditLogRepository;
import com.audit.pki.repos.implementations.CertificateRepository;
import org.junit.jupiter.api.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AuditLogRepositoryTest {

    private static DatabaseConnectionManager db;
    private static CertificateRepository certRepo;
    private static AuditLogRepository auditLogRepo;

    private static Certificate parentCert;
    private static String parentCertId;

    @BeforeAll
    static void setUpAll() throws Exception {
        // 1. Initialize DB Connection
        db = new DatabaseConnectionManager("jdbc:postgresql://localhost:5432/pki_audit",
                "audit_admin", "secure_password");

        certRepo = new CertificateRepository(db);
        auditLogRepo = new AuditLogRepository(db);

        // 2. Clean up any previous test runs
        db.getConnection().prepareStatement("DELETE FROM certificates WHERE serial_number = 'LOG-TEST-001'")
                .executeUpdate();

        // 3. Create and save a parent certificate to satisfy the Foreign Key constraint
        Instant validFrom = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        parentCert = new Certificate(
                "LOG-TEST-001",
                "log123thumbprintsha256",
                "CN=log.domain.com",
                "CN=Test CA",
                List.of("log.domain.com"),
                validFrom,
                validFrom.plus(30, ChronoUnit.DAYS),
                "SHA256withRSA",
                "RSA",
                2048,
                List.of("serverAuth"),
                "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----");

        certRepo.saveCertificate(parentCert);
        parentCertId = parentCert.getId().toString();
    }

    @Test
    @Order(1)
    void testSaveAndRetrieveAuditLog() {
        // Arrange: Create a mock JSON report string
        String detailsJson = "{\"isCompliant\":false,\"violations\":[\"Key size 1024 is strictly less than the required 2048 bits.\"],\"warnings\":[]}";

        // Use the Phase 2 constructor designed for new entries
        AuditLog newLog = new AuditLog(parentCertId, "NON_COMPLIANT", detailsJson);

        // Act & Assert 1: Verify it saves without SQL errors
        assertDoesNotThrow(() -> auditLogRepo.saveAuditLog(newLog),
                "Saving the audit log should not throw an exception");

        // Act 2: Retrieve the history for this certificate
        List<AuditLog> history = auditLogRepo.getLogsByCertificateId(parentCertId);

        // Assert 3: Verify the data was perfectly mapped back out of PostgreSQL
        assertFalse(history.isEmpty(), "The history list should contain our newly saved log.");
        assertEquals(1, history.size(), "There should be exactly one log in the history.");

        AuditLog retrievedLog = history.get(0);
        assertEquals("NON_COMPLIANT", retrievedLog.getStatusResult());

        // THE FIX: Parse the strings into JsonElements before comparing them
        assertEquals(
                JsonParser.parseString(detailsJson),
                JsonParser.parseString(retrievedLog.getDetails()),
                "JSONB reorders keys, so we must compare the parsed JSON objects, not the raw strings.");
    }

    @Test
    @Order(2)
    void testAuditLogsAreOrderedNewestFirst() throws InterruptedException {
        // Arrange: Wait a tiny fraction of a second to ensure a distinct timestamp
        Thread.sleep(10);

        // Create a SECOND log representing a successful re-audit
        String updatedDetailsJson = "{\"isCompliant\":true,\"violations\":[],\"warnings\":[]}";
        AuditLog newerLog = new AuditLog(parentCertId, "COMPLIANT", updatedDetailsJson);

        // Act
        auditLogRepo.saveAuditLog(newerLog);
        List<AuditLog> history = auditLogRepo.getLogsByCertificateId(parentCertId);

        // Assert: We should have 2 logs now
        assertEquals(2, history.size());

        // CRITICAL: Verify the DESCENDING order (newest first)
        assertEquals("COMPLIANT", history.get(0).getStatusResult(), "The newest log should be at index 0");
        assertEquals("NON_COMPLIANT", history.get(1).getStatusResult(), "The older log should be pushed to index 1");
    }
}