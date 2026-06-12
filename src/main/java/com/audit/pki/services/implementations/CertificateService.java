package com.audit.pki.services.implementations;

import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.services.interfaces.CertificateServiceInterface;

import com.audit.pki.shared.exceptions.*;
import com.audit.pki.shared.utils.CertificateExtractor;

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
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.ArrayList;

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
                    CertificateExtractor.calculateSha256Thumbprint(x509.getEncoded()), // Extracting Thumbprint
                    x509.getSubjectX500Principal().getName(), // Extracting Subject DN
                    x509.getIssuerX500Principal().getName(), // Extracting Issuer DN
                    CertificateExtractor.extractSanList(x509), // Extracting SANs (Helper needed)
                    x509.getNotBefore().toInstant(), // Extracting Valid From
                    x509.getNotAfter().toInstant(), // Extracting Valid To
                    x509.getSigAlgName(), // Extracting Signature Algorithm
                    x509.getPublicKey().getAlgorithm(), // Extracting Key Algorithm
                    CertificateExtractor.getKeySize(x509.getPublicKey()), // Extracting Key Size (Helper needed)
                    CertificateExtractor.extractExtendedKeyUsages(x509), // Extracting EKUs (Helper needed)
                    Base64.getEncoder().encodeToString(rawCertBytes) // Raw String representation
            );
            certificateRepository.saveCertificate(auditedCertificate);
            return auditedCertificate;
        } catch (CertificateEncodingException e) {
            throw new AuditParsingException("Failed to encode certificate for auditing.", e);
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
            throw new AuditParsingException("Invalid certificate format", e);
        }
    }

}
