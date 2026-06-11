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
        byte[] testCertBytes = Files.readAllBytes(Paths.get("test_rsa_cert.pem"));

        String expectedThumbprint = "2490D76C817294C04668BCD18809F3B43175A37E56B823E610CB57667EDF8211".toLowerCase();

        // Act: Run the public method
        Certificate result = certificateService.ingestCertificate(testCertBytes);

        // Assert: Verify the private helper did its job during the pipeline
        assertNotNull(result);
        assertEquals(expectedThumbprint, result.getThumbprintSha256());
    }

    @Test
    public void testIngestCertificate_ExtractsCorrectKeySize() throws Exception {
        // Arrange: Load the same Google certificate bytes
        byte[] testCertBytes = Files.readAllBytes(Paths.get("test_rsa_cert.pem"));

        // Act: Run the public orchestration method
        Certificate result = certificateService.ingestCertificate(testCertBytes);

        // Assert: Verify the domain model was populated with the correct integer
        assertNotNull(result, "The returned certificate should not be null.");

        // Replace 2048 with the actual key size of your downloaded certificate!
        int expectedKeySize = 2048;
        assertEquals(expectedKeySize, result.getKeySize(),
                "The extracted key size did not match the expected bit length.");
    }

}