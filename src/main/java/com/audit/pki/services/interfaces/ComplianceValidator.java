package com.audit.pki.services.interfaces;

import com.audit.pki.models.Certificate;
import java.util.List;

public interface ComplianceValidator {

    /**
     * A structured record containing the result of an audit.
     * 
     */
    record AuditReport(
            boolean isCompliant,
            List<String> violations,
            List<String> warnings) {
    }

    /**
     * Evaluates a certificate against specific compliance rules.
     *
     * @param certificate The mapped domain model to audit.
     * @return An AuditReport detailing any vulnerabilities.
     */
    AuditReport evaluate(Certificate certificate);
}