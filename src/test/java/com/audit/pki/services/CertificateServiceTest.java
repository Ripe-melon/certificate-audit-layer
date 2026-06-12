package com.audit.pki.services;

import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.services.implementations.CertificateService;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class CertificateServiceTest {

    private static final String TEST_CERT_PATH = "test_rsa_cert.pem";
    private static byte[] rawCertBytes;

    // 1. Create a fake "dummy" repository that doesn't connect to a real DB
    @Mock
    private CertificateRepository certificateRepository;

    // 2. Inject that fake repository into our real service
    @InjectMocks
    private CertificateService certificateService;

    @BeforeAll
    public static void setup() throws Exception {
        // All we need to do before the tests run is load our raw file into memory
        rawCertBytes = Files.readAllBytes(Paths.get(TEST_CERT_PATH));
    }

    @Test
    void testIngestCertificate_MapsAndSavesSuccessfully() {
        // Arrange
        String expectedThumbprint = "2490d76c817294c04668bcd18809f3b43175a37e56b823e610cb57667edf8211";

        // Act: Run the orchestration method
        Certificate result = certificateService.ingestCertificate(rawCertBytes);

        // Assert 1: Verify the orchestration correctly utilized the Extractors
        assertNotNull(result, "The service should return a fully mapped Certificate object");
        assertEquals(expectedThumbprint, result.getThumbprintSha256(),
                "The service did not map the thumbprint correctly.");
        assertEquals(2048, result.getKeySize(), "The service did not map the key size correctly.");

        // Assert 2: Verify the Behavioral Contract (The Magic of Mockito)
        // We verify that the service actually called 'saveCertificate' on our fake
        // repository exactly ONE time.
        verify(certificateRepository, times(1)).saveCertificate(result);
    }
}