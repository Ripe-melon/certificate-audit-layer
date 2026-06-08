package com.audit.pki.shared.exceptions;

/**
 * Thrown when a mathematically valid certificate fails the platform's strict
 * regulatory and security frameworks.
 * <p>
 * Examples include failing to meet minimum key size requirements (e.g., RSA
 * 2048-bit),
 * using deprecated signature algorithms (e.g., SHA-1), or violating specific
 * enterprise compliance mandates.
 * </p>
 */
public class ComplianceViolationException extends CertificateAuditException {

    /**
     * @param rule   The specific compliance rule that was breached (e.g.,
     *               "MIN_KEY_SIZE").
     * @param detail A human-readable explanation of the violation for audit logs.
     */
    public ComplianceViolationException(String rule, String detail) {
        super("Compliance violation [" + rule + "]: " + detail);
    }
}