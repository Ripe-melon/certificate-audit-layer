package com.audit.pki.services;

import com.audit.pki.models.Certificate;
import com.audit.pki.services.interfaces.ComplianceValidator;
import com.audit.pki.services.interfaces.ComplianceValidator.AuditReport;
import com.audit.pki.services.implementations.Nis2BaselineValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

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
                        String sigAlg, String templateName) { // <-- Added templateName here
                return new Certificate(
                                "TEST-SERIAL", "dummy-thumbprint", "CN=Test", "CN=Issuer",
                                List.of("test.domain.com"), validFrom, validTo, sigAlg, keyAlg, keySize,
                                List.of("1.3.6.1.5.5.7.3.1"), "raw_cert_string",
                                templateName, "Test Owner", "Test Deploy" // <-- Passed here
                );
        }

        @Test
        void testEvaluate_HappyPath_CompliantCertificate() {
                // Arrange: A perfectly valid, 2048-bit RSA cert, using SHA-256, valid for 100
                // days
                Certificate validCert = createTestCertificate(
                                now.minus(10, ChronoUnit.DAYS),
                                now.plus(90, ChronoUnit.DAYS),
                                "RSA", 2048, "SHA256withRSA", null);

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
                                "RSA", 1024, "SHA256withRSA", null);

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
                                "RSA", 2048, "MD5withRSA", null);

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
                                "RSA", 2048, "SHA256withRSA", null);

                // Act
                AuditReport report = validator.evaluate(longLifeCert);

                // Assert
                assertFalse(report.isCompliant());
                assertEquals(1, report.violations().size());
                // UPDATED STRING HERE:
                assertTrue(report.violations().get(0).contains("POLICY VIOLATION"));
        }

        @ParameterizedTest(name = "Lifespan of {0} days should have compliance: {1}")
        @CsvSource({
                        "397, true", // Just under the limit
                        "398, true", // Exactly on the boundary limit
                        "399, false" // Just over the limit (Poison pill)
        })
        void testLifespanUpperBoundaries(int daysToTest, boolean expectedCompliance) {
                // Arrange: Create a certificate that lives for exactly 'daysToTest' days
                Certificate boundaryCert = createTestCertificate(
                                now,
                                now.plus(daysToTest, ChronoUnit.DAYS),
                                "RSA", 2048, "SHA256withRSA", null);

                // Act
                AuditReport report = validator.evaluate(boundaryCert);

                // Assert: We don't hardcode true/false, we use the parameter!
                assertEquals(expectedCompliance, report.isCompliant(),
                                "Compliance check failed for lifespan of " + daysToTest + " days.");
        }

        @ParameterizedTest(name = "Lifespan of {0} days should result in compliance: {1}")
        @CsvSource({
                        "-1, false",
                        "0, false",
                        "1, true"
        })
        void testLifespanLowerBoundaries(int daysToTest, boolean expectedCompliance) {
                // Arrange: Start the cert 12 hours ago so it is currently active.
                Instant activeStart = now.minus(12, ChronoUnit.HOURS);

                // Add the test lifespan (e.g., if daysToTest is 1, it ends 12 hours from now)
                Instant testEnd = activeStart.plus(daysToTest, ChronoUnit.DAYS);

                Certificate boundaryCert = createTestCertificate(
                                activeStart, testEnd,
                                "RSA", 2048, "SHA256withRSA", null);

                // Act
                AuditReport report = validator.evaluate(boundaryCert);

                // Assert
                assertEquals(expectedCompliance, report.isCompliant(),
                                "Compliance check failed for lifespan of " + daysToTest + " days.");
        }

        @ParameterizedTest(name = "Expires in {0} days should trigger warning: {1}")
        @CsvSource({
                        "29, true", // Inside the warning window
                        "30, true", // Exactly on the boundary
                        "31, false" // Just outside the warning window
        })
        void testExpirationWarningBoundaries(int daysUntilExpiration, boolean expectWarning) {

                // Arrange: Start the cert 10 days ago.
                Instant start = now.minus(10, ChronoUnit.DAYS);

                // Add the test days, PLUS 1 minute of padding to defeat execution delays
                Instant end = now.plus(daysUntilExpiration, ChronoUnit.DAYS).plus(1, ChronoUnit.MINUTES);

                Certificate cert = createTestCertificate(start, end, "RSA", 2048, "SHA256withRSA", null);

                // Act
                AuditReport report = validator.evaluate(cert);

                // Assert: The cert is COMPLIANT, but the warnings list should change based on
                // the parameter
                assertTrue(report.isCompliant(), "Certificate should remain compliant despite warnings.");
                assertEquals(expectWarning, !report.warnings().isEmpty(),
                                "Warning logic failed for expiration in " + daysUntilExpiration + " days.");
        }

        @ParameterizedTest(name = "RSA Key Size of {0} bits should be compliant: {1}")
        @CsvSource({
                        "2047, false", // Just under the mathematical boundary
                        "2048, true", // Exactly on the baseline boundary
                        "4096, true" // Well over the boundary
        })
        void testRsaKeySizeBoundaries(int keySize, boolean expectedCompliance) {
                // Arrange: Use a safe timeline, only alter the key size
                Certificate cert = createTestCertificate(
                                now.minus(10, ChronoUnit.DAYS),
                                now.plus(90, ChronoUnit.DAYS),
                                "RSA", keySize, "SHA256withRSA", null);

                // Act
                AuditReport report = validator.evaluate(cert);

                // Assert
                assertEquals(expectedCompliance, report.isCompliant(),
                                "RSA key size boundary failed for size: " + keySize);
        }

        @Test
        void testEllipticCurveBypassesRsaSizeLimit() {
                // Arrange: 256 bits is a CRITICAL failure for RSA, but highly secure for ECDSA
                Certificate ecCert = createTestCertificate(
                                now.minus(10, ChronoUnit.DAYS),
                                now.plus(90, ChronoUnit.DAYS),
                                "ECDSA", 256, "SHA256withECDSA", null);

                // Act
                AuditReport report = validator.evaluate(ecCert);

                // Assert
                assertTrue(report.isCompliant(),
                                "Elliptic Curve algorithms should not be blocked by the RSA size limit.");
        }

        @org.junit.jupiter.params.ParameterizedTest(name = "Poison Pill Signature: ''{0}''")
        @org.junit.jupiter.params.provider.NullAndEmptySource
        @org.junit.jupiter.params.provider.ValueSource(strings = { "   " })
        void testEvaluate_SurvivesPoisonPillSignature(String poisonPillSig) {
                // Arrange: Create a certificate where ONLY the signature is corrupted
                Certificate corruptCert = createTestCertificate(
                                now.minus(10, ChronoUnit.DAYS),
                                now.plus(90, ChronoUnit.DAYS),
                                "RSA", 2048,
                                poisonPillSig // <-- Injecting the poison pill here (null, "", " ")
                                , null);

                // Act
                AuditReport report = validator.evaluate(corruptCert);

                // Assert: The system shouldn't crash. It should safely flag it.
                assertFalse(report.isCompliant(), "System should safely reject missing signatures.");

                boolean hasSignatureViolation = report.violations().stream()
                                .anyMatch(v -> v.contains("compromised") || v.contains("missing"));
                assertTrue(hasSignatureViolation, "Should log a signature violation.");
        }

        @Test
        void testEvaluate_SurvivesNullCertificate() {
                // Act: Pass an explicit null directly into the orchestrator
                AuditReport report = validator.evaluate(null);

                // Assert: It should return safely with a critical failure
                assertFalse(report.isCompliant(), "System should safely reject a completely null certificate.");

                boolean hasNullViolation = report.violations().stream()
                                .anyMatch(v -> v.contains("null and cannot be evaluated"));
                assertTrue(hasNullViolation, "Should log a specific master shield violation.");
        }

        @Test
        void testEvaluate_SurvivesNullTimestamps() {
                // Arrange: Create a certificate where validFrom and validTo are completely
                // missing
                Certificate corruptDateCert = createTestCertificate(
                                null, null,
                                "RSA", 2048, "SHA256withRSA", null);

                // Act
                AuditReport report = validator.evaluate(corruptDateCert);

                // Assert
                assertFalse(report.isCompliant(), "System should safely reject missing timestamps.");

                boolean hasTimeViolation = report.violations().stream()
                                .anyMatch(v -> v.contains("missing validFrom or validTo")); // <-- Updated string!
                assertTrue(hasTimeViolation, "Should log a missing timestamp violation.");
                assertTrue(hasTimeViolation, "Should log a missing timestamp violation.");
        }

        @org.junit.jupiter.params.ParameterizedTest(name = "Poison Pill Key Alg: ''{0}''")
        @org.junit.jupiter.params.provider.NullAndEmptySource
        @org.junit.jupiter.params.provider.ValueSource(strings = { "   " })
        void testEvaluate_SurvivesPoisonPillKeyAlgorithm(String poisonPillAlg) {
                // Arrange: Inject the poison pill into the keyAlg parameter
                Certificate corruptCert = createTestCertificate(
                                now.minus(10, ChronoUnit.DAYS),
                                now.plus(90, ChronoUnit.DAYS),
                                poisonPillAlg, 2048, "SHA256withRSA", null);

                // Act
                AuditReport report = validator.evaluate(corruptCert);

                // Assert
                assertFalse(report.isCompliant(), "System should safely reject missing key algorithms.");

                boolean hasAlgViolation = report.violations().stream()
                                .anyMatch(v -> v.contains("missing a public key algorithm"));
                assertTrue(hasAlgViolation, "Should log a missing key algorithm violation.");
        }
}