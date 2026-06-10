package com.audit.pki.services;

import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.services.implementations.CertificateService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
public class CertificateServiceTest {

    // 1. Create a fake, disconnected repository
    @Mock
    private CertificateRepository certificateRepository;

    // 2. Inject that fake repository into our real service
    @InjectMocks
    private CertificateService certificateService;

    @Test
    public void testIngestCertificate_CalculatesCorrectThumbprint() throws Exception {
        // Arrange: Load the certificate bytes straight from the root directory
        byte[] testCertBytes = Files.readAllBytes(Paths.get("google_cert.pem"));

        // Put your expected SHA-256 string here (see how to find it below)
        String expectedThumbprint = "33acfffd205bca23b2515985f85ba6a477f1302f8534b31029f276a5e016dfe8";
        // Act: Run the public method
        Certificate result = certificateService.ingestCertificate(testCertBytes);

        // Assert: Verify the private helper did its job during the pipeline
        assertNotNull(result);
        assertEquals(expectedThumbprint, result.getThumbprintSha256());
    }
}