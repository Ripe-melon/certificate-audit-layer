package com.audit.pki.repos;

import com.audit.pki.config.DatabaseConnectionManager;
import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import org.junit.jupiter.api.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CertificateRepositoryTest {

    private static CertificateRepository repository;
    private static Certificate testCert;
    private static DatabaseConnectionManager db;
    // CHANGED: This is now a UUID to match the new repository signature
    private static UUID certId;

    @BeforeAll
    static void setUpAll() throws Exception {
        db = new DatabaseConnectionManager("jdbc:postgresql://localhost:5432/pki_audit",
                "audit_admin", "secure_password");
        repository = new CertificateRepository(db);

        db.getConnection().prepareStatement("DELETE FROM certificates WHERE serial_number = 'TEST-SERIAL-001'")
                .executeUpdate();

        Instant validFrom = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Instant validTo = validFrom.plus(30, ChronoUnit.DAYS);

        testCert = new Certificate(
                "TEST-SERIAL-001",
                "abc123thumbprintsha256",
                "CN=test.domain.com",
                "CN=Test CA",
                List.of("test.domain.com", "www.test.domain.com"),
                validFrom,
                validTo,
                "SHA256withRSA",
                "RSA",
                2048,
                List.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"),
                "base64EncodedRawCertString");
    }

    @Test
    @Order(1)
    void testSaveCertificate() {
        // CHANGED: We now capture the returned UUID from the repository
        certId = repository.saveCertificate(testCert);

        assertNotNull(certId, "Database should generate and return a UUID");
        System.out.println("Saved certificate with true UUID: " + certId);
    }

    @Test
    @Order(2)
    void testGetCertificateById() {
        // CHANGED: We pass the UUID object directly
        Certificate fetched = repository.getCertificateById(certId);

        assertNotNull(fetched, "Should fetch the certificate we just saved");
        assertEquals("TEST-SERIAL-001", fetched.getSerialNumber());
        assertEquals("CN=test.domain.com", fetched.getSubjectDn());
        assertEquals(2048, fetched.getKeySize());
    }

    @Test
    @Order(3)
    void testGetCertificatesByStatus() {
        List<Certificate> unauditedCerts = repository.getCertificatesByAuditStatus("UNAUDITED");
        assertFalse(unauditedCerts.isEmpty(), "Should find at least one UNAUDITED certificate");

        boolean foundOurTestCert = unauditedCerts.stream()
                .anyMatch(c -> c.getSerialNumber().equals("TEST-SERIAL-001"));
        assertTrue(foundOurTestCert, "Our specific test cert should be in the UNAUDITED list");
    }

    @Test
    @Order(4)
    void testUpdateCertificate() {
        testCert.setRevoked(true);
        testCert.setAuditStatus("MANUAL_OVERRIDE");

        // Assuming your updateCertificate method still takes a String ID, OR you update
        // it to take UUID.
        // If you updated it to take UUID, pass certId. If you left it as String, pass
        // certId.toString().
        // For strict DDD, we assume you updated ALL repo methods to use UUID:
        int rows = repository.updateCertificate(certId, testCert);
        assertEquals(1, rows, "One row should be updated");

        Certificate updated = repository.getCertificateById(certId);
        assertTrue(updated.isRevoked());
    }

    @Test
    @Order(5)
    void testUpdateAuditState() {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        // Same assumption here regarding UUID vs String
        assertDoesNotThrow(() -> repository.updateAuditState(certId, "COMPLIANT", now),
                "Targeted audit update should not throw an exception");

        Certificate auditedCert = repository.getCertificateById(certId);
        assertEquals("COMPLIANT", auditedCert.getAuditStatus());
        assertNotNull(auditedCert.getLastAuditedAt());
        assertEquals(now, auditedCert.getLastAuditedAt());
    }

    @Test
    @Order(6)
    void testDeleteCertificate() {
        // Same assumption here regarding UUID vs String
        int rows = repository.deleteCertificate(certId);
        assertEquals(1, rows, "One row should be deleted");

        Certificate deleted = repository.getCertificateById(certId);
        assertNull(deleted, "Certificate should no longer exist in the database");
    }
}