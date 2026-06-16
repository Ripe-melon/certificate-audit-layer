package com.audit.pki.services;

import com.audit.pki.models.Certificate;
import com.audit.pki.services.interfaces.ComplianceValidator;
import com.audit.pki.services.interfaces.ComplianceValidator.AuditReport;
import com.audit.pki.services.implementations.Nis2BaselineValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class Nis2BaselineValidatorTest {

    private ComplianceValidator validator;
    private Instant now;

    @BeforeEach
    void setUp() {
        validator = new Nis2BaselineValidator();
        now = Instant.now();
    }

    /**
     * Helper method to quickly generate test certificates without copy-pasting
     * massive constructor blocks into every single test.
     */
    private Certificate createTestCertificate(Instant validFrom, Instant validTo, String keyAlg, int keySize,
            String sigAlg) {
        // Uses the Phase 2 constructor
        return new Certificate(
                "TEST-SERIAL", "dummy-thumbprint", "CN=Test", "CN=Issuer",
                List.of("test.domain.com"), validFrom, validTo, sigAlg, keyAlg, keySize,
                List.of("serverAuth"), "dummy-raw-string");
    }

    @Test
    void testEvaluate_HappyPath_CompliantCertificate() {
        // Arrange: A perfectly valid, 2048-bit RSA cert, using SHA-256, valid for 100
        // days
        Certificate validCert = createTestCertificate(
                now.minus(10, ChronoUnit.DAYS),
                now.plus(90, ChronoUnit.DAYS),
                "RSA", 2048, "SHA256withRSA");

        // Act
        AuditReport report = validator.evaluate(validCert);

        // Assert
        assertTrue(report.isCompliant(), "Certificate should be perfectly compliant.");
        assertTrue(report.violations().isEmpty(), "There should be zero violations.");
        assertTrue(report.warnings().isEmpty(), "There should be zero warnings.");
    }

    @Test
    void testEvaluate_FailsWhenRsaKeyIsTooSmall() {
        // Arrange: 1024-bit key (Too small)
        Certificate weakKeyCert = createTestCertificate(
                now.minus(10, ChronoUnit.DAYS),
                now.plus(90, ChronoUnit.DAYS),
                "RSA", 1024, "SHA256withRSA");

        // Act
        AuditReport report = validator.evaluate(weakKeyCert);

        // Assert
        assertFalse(report.isCompliant());
        assertEquals(1, report.violations().size());
        assertTrue(report.violations().get(0).contains("insecure RSA key size"));
    }

    @Test
    void testEvaluate_FailsWhenSignatureAlgorithmIsCompromised() {
        // Arrange: MD5 signature (Broken algorithm)
        Certificate badSigCert = createTestCertificate(
                now.minus(10, ChronoUnit.DAYS),
                now.plus(90, ChronoUnit.DAYS),
                "RSA", 2048, "MD5withRSA");

        // Act
        AuditReport report = validator.evaluate(badSigCert);

        // Assert
        assertFalse(report.isCompliant());
        assertEquals(1, report.violations().size());
        assertTrue(report.violations().get(0).contains("compromised signature algorithm"));
    }

    @Test
    void testEvaluate_FailsWhenLifespanExceedsMaximum() {
        // Arrange: Valid for 500 days (Exceeds the 398-day maximum)
        Certificate longLifeCert = createTestCertificate(
                now.minus(10, ChronoUnit.DAYS),
                now.plus(490, ChronoUnit.DAYS),
                "RSA", 2048, "SHA256withRSA");

        // Act
        AuditReport report = validator.evaluate(longLifeCert);

        // Assert
        assertFalse(report.isCompliant());
        assertEquals(1, report.violations().size());
        assertTrue(report.violations().get(0).contains("NIS2/CAB baseline maximum"));
    }
}