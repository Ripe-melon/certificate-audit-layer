package com.audit.pki.services.implementations;

import com.audit.pki.models.Certificate;
import com.audit.pki.services.interfaces.ComplianceValidator;

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
        boolean isCompliant = true;

        Instant now = Instant.now();
        Instant validFrom = certificate.getValidFrom();
        Instant validTo = certificate.getValidTo();

        // RULE 1: Is the certificate already expired?

        if (validTo.isBefore(now)) {
            isCompliant = false;
            violations.add("CRITICAL: Certificate has expired. Expiration date was: " + validTo);
        }

        // RULE 2: Is the certificate active yet?

        if (validFrom.isAfter(now)) {
            isCompliant = false;
            violations.add("INVALID: Certificate 'validFrom' date is in the future: " + validFrom);
        }

        // RULE 3: Does it violate the 398-day maximum lifespan?

        long lifespanDays = ChronoUnit.DAYS.between(validFrom, validTo);
        if (lifespanDays > MAX_LIFESPAN_DAYS) {
            isCompliant = false;
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

        return new AuditReport(isCompliant, violations, warnings);
    }
}