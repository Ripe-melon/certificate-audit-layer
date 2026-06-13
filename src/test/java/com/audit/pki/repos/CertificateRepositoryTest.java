package com.audit.pki.repos;

import com.audit.pki.config.DatabaseConnectionManager;
import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import org.junit.jupiter.api.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CertificateRepositoryTest {

    private static CertificateRepository repository;
    private static Certificate testCert;
    private static DatabaseConnectionManager db;
    private static String certIdString;

    @BeforeAll
    static void setUpAll() throws Exception {
        db = new DatabaseConnectionManager("jdbc:postgresql://localhost:5432/pki_audit",
                "audit_admin", "secure_password");
        repository = new CertificateRepository(db);

        db.getConnection().prepareStatement("DELETE FROM certificates WHERE serial_number = 'TEST-SERIAL-001'")
                .executeUpdate();

        // Pro-Tip: Truncate to MILLIS to prevent flaky precision failures between Java
        // and PostgreSQL
        Instant validFrom = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Instant validTo = validFrom.plus(30, ChronoUnit.DAYS);

        // Uses the Phase 2 constructor (12 arguments)
        testCert = new Certificate(
                "TEST-SERIAL-001",
                "abc123thumbprintsha256",
                "CN=test.domain.com, O=Audit",
                "CN=Test CA, O=Test",
                List.of("test.domain.com", "api.domain.com"),
                validFrom,
                validTo,
                "SHA256withRSA",
                "RSA",
                2048,
                List.of("serverAuth", "clientAuth"),
                "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----");
        certIdString = testCert.getId().toString();
    }

    @Test
    @Order(1)
    void testSaveCertificate() {
        assertDoesNotThrow(() -> repository.saveCertificate(testCert), "Saving should not throw an exception");

        // Verify our Phase 2 constructor logic worked perfectly (null timestamp on
        // first save)
        Certificate savedCert = repository.getCertificateById(certIdString);
        assertNull(savedCert.getLastAuditedAt(), "A brand new certificate should have a null last_audited_at");
        assertEquals("UNAUDITED", savedCert.getAuditStatus(), "A brand new certificate should default to UNAUDITED");
    }

    @Test
    @Order(2)
    void testGettersAndExistence() {
        Certificate byId = repository.getCertificateById(certIdString);
        assertNotNull(byId);
        assertEquals("TEST-SERIAL-001", byId.getSerialNumber());

        Certificate bySerial = repository.getCertificateBySerialNumber("TEST-SERIAL-001");
        assertNotNull(bySerial);

        Certificate byThumb = repository.getCertificateByThumbprint("abc123thumbprintsha256");
        assertNotNull(byThumb);

        assertTrue(repository.existsByThumbprint("abc123thumbprintsha256"));
        assertFalse(repository.existsByThumbprint("fake-thumbprint"));
    }

    @Test
    @Order(3)
    void testListQueries() {
        List<Certificate> byIssuer = repository.getCertificatesByIssuerDn("CN=Test CA, O=Test");
        assertFalse(byIssuer.isEmpty());

        List<Certificate> byDomain = repository.getCertificatesByDomain("api.domain.com");
        assertFalse(byDomain.isEmpty());

        List<String> eku = repository.getCertificateExtendedKeyUsage(certIdString);
        assertTrue(eku.contains("serverAuth"));

        List<Certificate> byStatus = repository.getCertificatesByAuditStatus("UNAUDITED");
        assertFalse(byStatus.isEmpty());

        List<Certificate> expiring = repository.getCertificatesExpiringWithinDays(40);
        assertFalse(expiring.isEmpty());

        List<Certificate> all = repository.getAllCertificates();
        assertFalse(all.isEmpty());
    }

    @Test
    @Order(4)
    void testUpdateCertificate() {
        // Mutate the state for general updates (e.g., revoking a cert manually)
        testCert.setRevoked(true);
        testCert.setAuditStatus("MANUAL_OVERRIDE");

        int rows = repository.updateCertificate(certIdString, testCert);
        assertEquals(1, rows, "One row should be updated");

        Certificate updated = repository.getCertificateById(certIdString);
        assertTrue(updated.isRevoked());
    }

    @Test
    @Order(5)
    void testUpdateAuditState() {
        // Test the brand new highly-focused method from Phase 3
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        assertDoesNotThrow(() -> repository.updateAuditState(certIdString, "COMPLIANT", now),
                "Targeted audit update should not throw an exception");

        // Verify the database caught the exact time and new status
        Certificate auditedCert = repository.getCertificateById(certIdString);
        assertEquals("COMPLIANT", auditedCert.getAuditStatus());
        assertNotNull(auditedCert.getLastAuditedAt());
        assertEquals(now, auditedCert.getLastAuditedAt());
    }

    @Test
    @Order(6)
    void testDeleteCertificate() {
        int rows = repository.deleteCertificate(certIdString);
        assertEquals(1, rows, "One row should be deleted");

        Certificate deleted = repository.getCertificateById(certIdString);
        assertNull(deleted, "Certificate should no longer exist in the database");
    }
}