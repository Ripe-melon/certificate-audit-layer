package com.audit.pki.shared.exceptions;

import java.util.UUID;

/**
 * Thrown when a specific operation (e.g., update, delete, or targeted lookup)
 * requests a certificate that cannot be found in the underlying repository.
 */
public class CertificateNotFoundException extends CertificateAuditException {
    public CertificateNotFoundException(UUID id) {
        super("Certificate with ID " + id + " was not found.");
    }

    public CertificateNotFoundException(String identifier) {
        super("Certificate with identifier '" + identifier + "' was not found.");
    }
}