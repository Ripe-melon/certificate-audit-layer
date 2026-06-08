package com.audit.pki.shared.exceptions;

/**
 * Base exception for all domain-specific errors within the certificate audit
 * platform.
 * <p>
 * This abstract exception is designed to isolate business logic, cryptographic
 * state,
 * and NIS2 regulatory compliance violations from generic Java runtime
 * exceptions.
 * By catching this parent class at the API layer, the application can uniformly
 * translate domain errors into standardized HTTP responses.
 * </p>
 */
public class CertificateAuditException extends RuntimeException {
    public CertificateAuditException(String message) {
        super(message);
    }

    public CertificateAuditException(String message, Throwable cause) {
        super(message, cause);
    }

}
