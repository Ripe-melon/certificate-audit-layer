package com.audit.pki.shared.exceptions;

/**
 * Thrown when a certificate violates basic X.509 lifecycle rules during
 * processing.
 * <p>
 * This is most commonly triggered when attempting to ingest or audit a
 * certificate
 * that has already expired or whose valid_from date lies in the future.
 * </p>
 */
public class CertificateValidationException extends CertificateAuditException {
    public CertificateValidationException(String message) {
        super("Certificate validation failed: " + message);
    }
}