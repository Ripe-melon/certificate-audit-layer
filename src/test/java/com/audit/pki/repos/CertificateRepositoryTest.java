package com.audit.pki.repos;

import com.audit.pki.config.DatabaseConnectionManager;
import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import org.junit.jupiter.api.*;

import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CertificateRepositoryTest {

    private static CertificateRepository repository;
    private static Certificate testCert;
    private static DatabaseConnectionManager db;
    private static String certIdString;

    @BeforeAll
    static void setUpAll() throws Exception {
        // Initialize your database connection manager here.
        // Assuming Database is an interface or class you've created

        db = new DatabaseConnectionManager("jdbc:postgresql://localhost:5432/pki_audit",
                "audit_admin", "secure_password");
        repository = new CertificateRepository(db);

        db.getConnection().prepareStatement("DELETE FROM certificates WHERE serial_number = 'TEST-SERIAL-001'")
                .executeUpdate();

        // Create a single test certificate to use across all tests
        testCert = new Certificate(
                "TEST-SERIAL-001",
                "abc123thumbprintsha256",
                "CN=test.domain.com, O=Audit",
                "CN=Test CA, O=Test",
                List.of("test.domain.com", "api.domain.com"),
                Instant.now(),
                Instant.now().plus(30, ChronoUnit.DAYS),
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
    }

    @Test
    @Order(2)
    void testGettersAndExistence() throws SQLException {
        // Test ID lookup
        Certificate byId = repository.getCertificateById(certIdString);
        assertNotNull(byId);
        assertEquals("TEST-SERIAL-001", byId.getSerialNumber());

        // Test Serial lookup
        Certificate bySerial = repository.getCertificateBySerialNumber("TEST-SERIAL-001");
        assertNotNull(bySerial);

        // Test Thumbprint lookup
        Certificate byThumb = repository.getCertificateByThumbprint("abc123thumbprintsha256");
        assertNotNull(byThumb);

        // Test Exists
        assertTrue(repository.existsByThumbprint("abc123thumbprintsha256"));
        assertFalse(repository.existsByThumbprint("fake-thumbprint"));
    }

    @Test
    @Order(3)
    void testListQueries() throws SQLException {
        // Test Issuer
        List<Certificate> byIssuer = repository.getCertificatesByIssuerDn("CN=Test CA, O=Test");
        assertFalse(byIssuer.isEmpty());

        // Test Domain (JSONB @> operator)
        List<Certificate> byDomain = repository.getCertificatesByDomain("api.domain.com");
        assertFalse(byDomain.isEmpty());

        // Test Extended Key Usage
        List<String> eku = repository.getCertificateExtendedKeyUsage(certIdString);
        assertTrue(eku.contains("serverAuth"));

        // Test Audit Status
        List<Certificate> byStatus = repository.getCertificatesByAuditStatus("UNAUDITED");
        assertFalse(byStatus.isEmpty());

        // Test Expiration (Within 40 days, should catch our 30-day cert)
        List<Certificate> expiring = repository.getCertificatesExpiringWithinDays(40);
        assertFalse(expiring.isEmpty());

        // Test Get All
        List<Certificate> all = repository.getAllCertificates();
        assertFalse(all.isEmpty());
    }

    @Test
    @Order(4)
    void testUpdateCertificate() throws SQLException {
        // Mutate the state
        testCert.setRevoked(true);
        testCert.setAuditStatus("COMPLIANT");

        int rows = repository.updateCertificate(certIdString, testCert);
        assertEquals(1, rows, "One row should be updated");

        // Verify the update took place
        Certificate updated = repository.getCertificateById(certIdString);
        assertTrue(updated.isRevoked());
        assertEquals("COMPLIANT", updated.getAuditStatus());
    }

    @Test
    @Order(5)
    void testDeleteCertificate() throws SQLException {
        int rows = repository.deleteCertificate(certIdString);
        assertEquals(1, rows, "One row should be deleted");

        // Verify it's gone
        Certificate deleted = repository.getCertificateById(certIdString);
        assertNull(deleted, "Certificate should no longer exist in the database");
    }
}