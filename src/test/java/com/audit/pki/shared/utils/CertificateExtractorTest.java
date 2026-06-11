package com.audit.pki.shared.utils;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CertificateExtractorTest {

    private static byte[] rawCertBytes;
    private static X509Certificate x509Cert;

    /**
     * The Setup Phase: Loads the physical file and parses it into a native
     * Java certificate object ONCE before any tests run.
     */
    @BeforeAll
    public static void setup() throws Exception {
        // Load the bytes from the root directory
        rawCertBytes = Files.readAllBytes(Paths.get("test_rsa_cert.pem"));

        // Parse it natively so we can test the specific extraction methods
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream stream = new ByteArrayInputStream(rawCertBytes)) {
            x509Cert = (X509Certificate) factory.generateCertificate(stream);
        }
    }

    @Test
    public void testCalculateSha256Thumbprint_ReturnsCorrectHash() throws Exception {
        // Arrange
        String expectedThumbprint = "2490d76c817294c04668bcd18809f3b43175a37e56b823e610cb57667edf8211";

        // Act: Call the static utility method directly using the encoded bytes
        String actualThumbprint = CertificateExtractor.calculateSha256Thumbprint(x509Cert.getEncoded());

        // Assert
        assertNotNull(actualThumbprint);
        assertEquals(expectedThumbprint, actualThumbprint, "The computed SHA-256 thumbprint did not match.");
    }

    @Test
    public void testGetKeySize_ReturnsCorrectBitLength() {
        // Arrange
        int expectedKeySize = 2048;

        // Act: Pass the extracted public key directly to the static method
        int actualKeySize = CertificateExtractor.getKeySize(x509Cert.getPublicKey());

        // Assert
        assertEquals(expectedKeySize, actualKeySize,
                "The extracted RSA key size did not match the expected 2048 bits.");
    }
}