package com.audit.pki.shared.exceptions;

/**
 * Thrown when attempting to ingest a certificate that already exists within the
 * system.
 * <p>
 * Identity is verified via the certificate's unique SHA-256 thumbprint to
 * prevent
 * duplicate audit entries and ensure database integrity.
 * </p>
 */
public class DuplicateCertificateException extends CertificateAuditException {
    public DuplicateCertificateException(String thumbprint) {
        super("A certificate with thumbprint " + thumbprint + " already exists in the system.");
    }
}