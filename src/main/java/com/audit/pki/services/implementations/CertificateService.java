package com.audit.pki.services.implementations;

import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.services.interfaces.CertificateServiceInterface;

import com.audit.pki.shared.exceptions.*;

import java.util.UUID;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

public class CertificateService implements CertificateServiceInterface {

    private final CertificateRepository certificateRepository;

    public CertificateService(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Override
    public Certificate ingestCertificate(byte[] rawCertBytes) {
        X509Certificate x509 = parseToX509(rawCertBytes);
        try {
            Certificate auditedCertificate = new Certificate(
                    x509.getSerialNumber().toString(), // Extracting Serial
                    calculateSha256Thumbprint(x509.getEncoded()), // Extracting Thumbprint
                    x509.getSubjectX500Principal().getName(), // Extracting Subject DN
                    x509.getIssuerX500Principal().getName(), // Extracting Issuer DN
                    extractSanList(x509), // Extracting SANs (Helper needed)
                    x509.getNotBefore().toInstant(), // Extracting Valid From
                    x509.getNotAfter().toInstant(), // Extracting Valid To
                    x509.getSigAlgName(), // Extracting Signature Algorithm
                    x509.getPublicKey().getAlgorithm(), // Extracting Key Algorithm
                    getKeySize(x509.getPublicKey()), // Extracting Key Size (Helper needed)
                    extractExtendedKeyUsages(x509), // Extracting EKUs (Helper needed)
                    Base64.getEncoder().encodeToString(rawCertBytes) // Raw String representation
            );
            return auditedCertificate;
        } catch (CertificateEncodingException e) {
            throw new CertificateParsingException("Failed to encode certificate for auditing.", e);
        }
    }

    @Override
    public Certificate getCertificateById(UUID id) {
        // Implementation here
        return null;
    }

    /**
     * Helpermethod transforming incoming bytes into a native Java X509Certificate
     * object.
     * 
     * @param rawCertBytes
     * @return
     */
    private X509Certificate parseToX509(byte[] rawCertBytes) {
        try (InputStream stream = new ByteArrayInputStream(rawCertBytes)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(stream);
        } catch (CertificateException | IOException e) {
            throw new CertificateParsingException("Invalid certificate format", e);
        }
    }

    private String calculateSha256Thumbprint(byte[] certBytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(certBytes);

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                // "%02x" forces each byte to be represented as 2 lowercase hex digits
                hexString.append(String.format("%02x", b));
            }
            String thumbprint = hexString.toString();

            return thumbprint;
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateValidationException("Invalid Algorithm.");
        }
    }

    private List<String> extractSanList(X509Certificate cert) {
        // Implementation for extracting Subject Alternative Names
        return null;
    }

    private int getKeySize(java.security.PublicKey publicKey) {
        // Implementation for determining key size based on algorithm
        return 0;
    }

    private List<String> extractExtendedKeyUsages(X509Certificate cert) {
        // Implementation for extracting Extended Key Usages
        return null;
    }
}
