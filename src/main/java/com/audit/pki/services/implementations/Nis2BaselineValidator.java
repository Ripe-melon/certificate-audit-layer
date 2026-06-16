package com.audit.pki.services.implementations;

import com.audit.pki.models.Certificate;
import com.audit.pki.services.interfaces.ComplianceValidator;
import com.audit.pki.shared.utils.CertificateExtractor;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

public class Nis2BaselineValidator implements ComplianceValidator {

    // Modern compliance strictly limits public certs to 398 days
    private static final int MAX_LIFESPAN_DAYS = 398;
    // We want to alert the team if a cert dies in the next 30 days
    private static final int EXPIRATION_WARNING_DAYS = 30;

    @Override
    public AuditReport evaluate(Certificate certificate) {
        List<String> violations = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // 1. Run Chronological Checks
        validateLifespan(certificate, violations, warnings);

        // 2. Run Cryptographic Checks
        validateKeyStrength(certificate, violations);
        validateSignatureAlgorithm(certificate, violations);

        // 3. Determine Final Status
        boolean isCompliant = violations.isEmpty();

        return new AuditReport(isCompliant, violations, warnings);
    }

    private void validateLifespan(Certificate certificate, List<String> violations, List<String> warnings) {
        Instant now = Instant.now();
        Instant validFrom = certificate.getValidFrom();
        Instant validTo = certificate.getValidTo();

        // RULE 1: Is the certificate already expired?

        if (validTo.isBefore(now)) {
            violations.add("CRITICAL: Certificate has expired. Expiration date was: " + validTo);
        }

        // RULE 2: Is the certificate active yet?

        if (validFrom.isAfter(now)) {
            violations.add("INVALID: Certificate 'validFrom' date is in the future: " + validFrom);
        }

        // RULE 3: Does it violate the 398-day maximum lifespan?

        long lifespanDays = ChronoUnit.DAYS.between(validFrom, validTo);
        if (lifespanDays <= 0) {
            violations.add("INVALID: Certificate lifespan must be at least 1 day.");
        } else if (lifespanDays > MAX_LIFESPAN_DAYS) {
            violations.add(String.format(
                    "COMPLIANCE VIOLATION: Certificate lifespan is %d days. NIS2/CAB baseline maximum is %d days.",
                    lifespanDays, MAX_LIFESPAN_DAYS));
        }
        // RULE 4: Is it expiring soon? (Only check if not already expired)
        if (validTo.isAfter(now)) {
            long daysUntilExpiration = ChronoUnit.DAYS.between(now, validTo);
            if (daysUntilExpiration <= EXPIRATION_WARNING_DAYS) {
                warnings.add(String.format(
                        "WARNING: Certificate is expiring in %d days. Rotation required.",
                        daysUntilExpiration));
            }
        }

    }

    private void validateKeyStrength(Certificate certificate, List<String> violations) {
        String keyAlg = certificate.getKeyAlgorithm();
        int keySize = certificate.getKeySize();

        if ("RSA".equalsIgnoreCase(keyAlg) && keySize < 2048) {
            violations.add(String.format(
                    "CRITICAL: Certificate uses an insecure RSA key size of %d bits (Minimum is 2048).",
                    keySize));
        }
    }

    private void validateSignatureAlgorithm(Certificate certificate, List<String> violations) {
        String sigAlg = certificate.getSignatureAlgorithm().toUpperCase();

        if (sigAlg.contains("MD5") || sigAlg.contains("SHA1")) {
            violations.add("CRITICAL: Certificate uses a compromised signature algorithm: " + sigAlg);
        }
    }
}