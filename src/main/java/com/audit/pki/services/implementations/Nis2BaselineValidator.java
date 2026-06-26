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

        if (certificate == null) {
            violations.add("CRITICAL: The provided certificate object is null and cannot be evaluated.");
            return new AuditReport(false, violations, warnings);
        }

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

        if (validFrom == null || validTo == null) {
            violations.add("CRITICAL: Certificate is missing validFrom or validTo timestamps.");
            return; // Exit early to prevent math errors!
        }

        // 1. Dynamic Policy Lookup: Ask the engine what the limit is for THIS specific
        // certificate
        int allowedLifespanDays = determineAllowedLifespan(certificate.getTemplateName());

        // 2. Calculate the actual mathematical lifespan
        long lifespanDays = ChronoUnit.DAYS.between(validFrom, validTo);

        if (lifespanDays <= 0) {
            violations.add("CRITICAL: Certificate lifespan must be at least 1 day.");
        } else if (lifespanDays > allowedLifespanDays) {
            // 3. Context-Aware Violation Message
            String templateDisplay = (certificate.getTemplateName() != null)
                    ? "'" + certificate.getTemplateName() + "' template"
                    : "default baseline";

            violations.add(String.format(
                    "POLICY VIOLATION: Certificate lifespan is %d days. The %s restricts this to a maximum of %d days.",
                    lifespanDays, templateDisplay, allowedLifespanDays));
        }

        // 4. Check if currently expired
        if (validTo.isBefore(now)) {
            violations.add("CRITICAL: Certificate has expired.");
        } else {
            // 5. Check warning window (approaching expiration)
            long daysUntilExpiration = ChronoUnit.DAYS.between(now, validTo);
            if (daysUntilExpiration <= EXPIRATION_WARNING_DAYS) {
                warnings.add(String.format(
                        "WARNING: Certificate expires in %d days. Renewal or rotation required.",
                        daysUntilExpiration));
            }
        }
    }

    /**
     * A lightweight Rules Engine that mimics the company's internal PKI Policy
     * (CP/CPS).
     * Maps Microsoft ADCS Template names to their approved maximum lifespans.
     */
    private int determineAllowedLifespan(String templateName) {
        // If no template is provided (e.g., a Public Web SSL cert), strictly enforce
        // the NIS2 baseline
        if (templateName == null || templateName.trim().isEmpty()) {
            return MAX_LIFESPAN_DAYS; // 398 days
        }

        String normalizedTemplate = templateName.toLowerCase();

        // ADCS Rule 1: SAP, Printers, and Wireless Auth are granted 2-year exceptions
        if (normalizedTemplate.contains("sap") ||
                normalizedTemplate.contains("printers") ||
                normalizedTemplate.contains("wireless")) {
            return 730;
        }

        // ADCS Rule 2: Citrix Smartcard Logon is highly sensitive and restricted to 1
        // week
        if (normalizedTemplate.contains("smartcard")) {
            return 7;
        }

        // ADCS Rule 3: Time Stamping and modern Web SSL fallback to the standard 398
        // days
        return MAX_LIFESPAN_DAYS;
    }

    private void validateKeyStrength(Certificate certificate, List<String> violations) {
        String keyAlg = certificate.getKeyAlgorithm();

        if (keyAlg == null || keyAlg.trim().isEmpty()) {
            violations.add("CRITICAL: Certificate is missing a public key algorithm.");
            return;
        }

        int keySize = certificate.getKeySize();
        if ("RSA".equalsIgnoreCase(keyAlg) && keySize < 2048) {
            violations.add(String.format(
                    "CRITICAL: Certificate uses an insecure RSA key size of %d bits (Minimum is 2048).",
                    keySize));
        }
    }

    private void validateSignatureAlgorithm(Certificate certificate, List<String> violations) {
        String rawSigAlg = certificate.getSignatureAlgorithm();

        // 1. The Defensive Shield: Catch nulls and empty strings immediately
        if (rawSigAlg == null || rawSigAlg.trim().isEmpty()) {
            violations.add("CRITICAL: Certificate is missing a signature algorithm.");
            return; // Exit the method safely before we try to call .toUpperCase()
        }

        // 2. The Standard Math: Now it is safe to process
        String sigAlg = rawSigAlg.toUpperCase();
        if (sigAlg.contains("MD5") || sigAlg.contains("SHA1")) {
            violations.add("CRITICAL: Certificate uses a compromised signature algorithm: " + sigAlg);
        }
    }
}