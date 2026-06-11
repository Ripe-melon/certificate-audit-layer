package com.audit.pki.services;

import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.services.implementations.CertificateService;
import com.audit.pki.shared.utils.CertificateExtractor;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

@ExtendWith(MockitoExtension.class)
public class CertificateServiceTest {

    // 1. Create a fake, disconnected repository
    @Mock
    private CertificateRepository certificateRepository;

    // 2. Inject that fake repository into our real service
    @InjectMocks
    private CertificateService certificateService;

    private static byte[] rawCertBytes;
    private static java.security.cert.X509Certificate x509Cert;

    @BeforeAll
    public static void setup() {
        try {
            // Load the bytes from the root directory
            rawCertBytes = Files.readAllBytes(Paths.get("test_rsa_cert.pem"));

            // Parse it natively so we can test the specific extraction methods
            java.security.cert.CertificateFactory factory = java.security.cert.CertificateFactory.getInstance("X.509");
            try (InputStream stream = new java.io.ByteArrayInputStream(rawCertBytes)) {
                x509Cert = (java.security.cert.X509Certificate) factory.generateCertificate(stream);
            }
        } catch (Exception e) {
            fail("Setup failed: " + e.getMessage());
        }

    }

    @Test
    public void testIngestCertificate_CalculatesCorrectThumbprint() throws Exception {

        String expectedThumbprint = "2490D76C817294C04668BCD18809F3B43175A37E56B823E610CB57667EDF8211".toLowerCase();

        // Act: Run the public method
        Certificate result = certificateService.ingestCertificate(rawCertBytes);

        // Assert: Verify the private helper did its job during the pipeline
        assertNotNull(result);
        assertEquals(expectedThumbprint, result.getThumbprintSha256());
    }

    @Test
    public void testIngestCertificate_ExtractsCorrectKeySize() throws Exception {


        // Act: Run the public orchestration method
        Certificate result = certificateService.ingestCertificate(rawCertBytes);

        // Assert: Verify the domain model was populated with the correct integer
        assertNotNull(result, "The returned certificate should not be null.");

        // Replace 2048 with the actual key size of your downloaded certificate!
        int expectedKeySize = 2048;
        assertEquals(expectedKeySize, result.getKeySize(),
                "The extracted key size did not match the expected bit length.");
    }

    @Test
    public void testExtractExtendedKeyUsages_HandlesCertWithoutEkus() {

        // Act: Extract the EKUs from our pre-loaded test certificate
        List<String> actualEkus = CertificateExtractor.extractExtendedKeyUsages(x509Cert);

        // Assert:
        // 1. Verify our method caught the null and returned an actual list object
        assertNotNull(actualEkus, "The returned list should not be null to prevent database crashes.");

        // 2. Verify the list is empty, accurately reflecting our basic test certificate
        assertTrue(actualEkus.isEmpty(), "The basic OpenSSL test certificate should not contain any EKUs.");
    }

}