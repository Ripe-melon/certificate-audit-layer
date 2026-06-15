package com.audit.pki.services;

import com.audit.pki.models.AuditLog;
import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.repos.interfaces.AuditLogRepositoryInterface;
import com.audit.pki.services.implementations.CertificateService;
import com.audit.pki.services.interfaces.ComplianceValidator;
import com.audit.pki.services.interfaces.ComplianceValidator.AuditReport;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CertificateServiceTest {

    private static final String TEST_CERT_PATH = "test_rsa_cert.pem";
    private static byte[] rawCertBytes;

    // 1. Mock the Database Repositories
    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private AuditLogRepositoryInterface auditLogRepository;

    // 2. Mock the Validation Engine
    @Mock
    private ComplianceValidator validator;

    // 3. Inject all 3 mocks into the real service automatically
    @InjectMocks
    private CertificateService certificateService;

    @BeforeAll
    public static void setup() throws Exception {
        rawCertBytes = Files.readAllBytes(Paths.get(TEST_CERT_PATH));
    }

    @Test
    void testIngestCertificate_MapsAndSavesSuccessfully() {
        // Arrange: Expected extraction values
        String expectedThumbprint = "2490d76c817294c04668bcd18809f3b43175a37e56b823e610cb57667edf8211";

        // Arrange: Teach the mock validator how to respond so it doesn't throw a
        // NullPointerException
        AuditReport dummyReport = new AuditReport(true, List.of(), List.of());
        when(validator.evaluate(any(Certificate.class))).thenReturn(dummyReport);

        // Act: Run the orchestration method (Ingest -> Save -> Audit -> Save Log ->
        // Update State)
        Certificate result = certificateService.ingestCertificate(rawCertBytes);

        // Assert 1: Verify the extraction worked
        assertNotNull(result, "The service should return a fully mapped Certificate object");
        assertEquals(expectedThumbprint, result.getThumbprintSha256(),
                "The service did not map the thumbprint correctly.");
        assertEquals(2048, result.getKeySize(), "The service did not map the key size correctly.");

        // Assert 2: Verify the state was updated in memory before returning
        assertEquals("COMPLIANT", result.getAuditStatus());
        assertNotNull(result.getLastAuditedAt());

        // Assert 3: Verify the Behavioral Contract (The exact orchestration steps)
        // Step A: Did we save the initial UNAUDITED certificate?
        verify(certificateRepository, times(1)).saveCertificate(result);

        // Step B: Did we actually ask the validator to evaluate it?
        verify(validator, times(1)).evaluate(result);

        // Step C: Did we write the history log?
        verify(auditLogRepository, times(1)).saveAuditLog(any(AuditLog.class));

        // Step D: Did we update the certificate state in the database?
        verify(certificateRepository, times(1)).updateAuditState(
                eq(result.getId().toString()),
                eq("COMPLIANT"),
                any(Instant.class));
    }
}