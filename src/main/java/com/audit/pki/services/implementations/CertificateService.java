package com.audit.pki.services.implementations;

import com.audit.pki.models.AuditLog;
import com.audit.pki.models.Certificate;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.repos.interfaces.AuditLogRepositoryInterface;
import com.audit.pki.services.interfaces.CertificateServiceInterface;
import com.audit.pki.services.interfaces.ComplianceValidator;
import com.audit.pki.services.interfaces.ComplianceValidator.AuditReport;
import com.audit.pki.shared.exceptions.*;
import com.audit.pki.shared.utils.CertificateExtractor;
import com.google.gson.Gson;

import java.util.UUID;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

public class CertificateService implements CertificateServiceInterface {

    private final CertificateRepository certificateRepository;
    private final AuditLogRepositoryInterface auditLogRepository;
    private final ComplianceValidator validator;
    private final Gson gson;

    // Updated Constructor to include the new dependencies
    public CertificateService(CertificateRepository certificateRepository,
            AuditLogRepositoryInterface auditLogRepository,
            ComplianceValidator validator) {
        this.certificateRepository = certificateRepository;
        this.auditLogRepository = auditLogRepository;
        this.validator = validator;
        this.gson = new Gson();
    }

    @Override
    public Certificate ingestCertificate(byte[] rawCertBytes) {
        X509Certificate x509 = parseToX509(rawCertBytes);
        try {
            Certificate certificate = new Certificate(
                    x509.getSerialNumber().toString(),
                    CertificateExtractor.calculateSha256Thumbprint(x509.getEncoded()),
                    x509.getSubjectX500Principal().getName(),
                    x509.getIssuerX500Principal().getName(),
                    CertificateExtractor.extractSanList(x509),
                    x509.getNotBefore().toInstant(),
                    x509.getNotAfter().toInstant(),
                    x509.getSigAlgName(),
                    x509.getPublicKey().getAlgorithm(),
                    CertificateExtractor.getKeySize(x509.getPublicKey()),
                    CertificateExtractor.extractExtendedKeyUsages(x509),
                    Base64.getEncoder().encodeToString(rawCertBytes));

            // 3. Save to the database and capture the TRUE UUID
            // (Using the updated saveCertificate method that returns UUID)
            UUID trueId = certificateRepository.saveCertificate(certificate);

            // 4. Resolve the "Identity Crisis" WITHOUT using a Setter
            if (!trueId.equals(certificate.getId())) {
                // If the IDs don't match, it means this was a duplicate and PostgreSQL
                // kept the old ID. Since we refuse to use setId() to protect the domain model,
                // we MUST fetch the correct, existing object from the database.

                // Note: You will need a quick findById method in your repository for this!
                certificate = certificateRepository.getCertificateById(trueId);
            }

            // 5. Perform the mathematical audit on the mathematically correct object
            // Now when performAudit writes to the audit_logs table, certificate.getId() is
            // 100% accurate.
            performAudit(certificate);

            return certificate;

        } catch (CertificateEncodingException e) {
            throw new AuditParsingException("Failed to encode certificate for auditing.", e);
        }
    }

    public List<Certificate> getAllCertificates() {
        System.out.println("Service: Fetching all certificates from database...");
        return certificateRepository.getAllCertificates();
    }

    @Override
    public Certificate getCertificateById(UUID id) {
        // Implementation here
        return null;
    }

    /**
     * The core orchestration method.
     * It runs the math, updates the state, and writes the history.
     */
    @Override
    public void performAudit(Certificate certificate) {
        // 1. Run the pure business logic (No database involved yet)
        AuditReport report = validator.evaluate(certificate);

        // 2. Determine the high-level status string
        String statusResult = report.isCompliant() ? "COMPLIANT" : "NON_COMPLIANT";
        if (report.isCompliant() && !report.warnings().isEmpty()) {
            statusResult = "WARNING_EXPIRING_SOON";
        }

        // 3. Translate the Report into JSON for the Audit Log
        String detailsJson = gson.toJson(report);

        // 4. Lock in the exact time of the audit
        Instant auditTime = Instant.now();

        // 5. Update the Java Object in memory so the returned object is accurate
        certificate.setAuditStatus(statusResult);
        certificate.setLastAuditedAt(auditTime);

        // 6. INFRASTRUCTURE CALL A: Write the immutable history
        AuditLog newLog = new AuditLog(certificate.getId().toString(), statusResult, detailsJson);
        auditLogRepository.saveAuditLog(newLog);

        // 7. INFRASTRUCTURE CALL B: Update the current state in PostgreSQL
        certificateRepository.updateAuditState(certificate.getId(), statusResult, auditTime);
    }

    private X509Certificate parseToX509(byte[] rawCertBytes) {
        try (InputStream stream = new ByteArrayInputStream(rawCertBytes)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(stream);
        } catch (CertificateException | IOException e) {
            throw new AuditParsingException("Invalid certificate format", e);
        }
    }
}