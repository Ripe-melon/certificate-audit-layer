package com.audit.pki.shared.exceptions;

/**
 * Thrown when the application receives raw cryptographic data that cannot be
 * successfully parsed into a valid X.509 certificate object.
 * <p>
 * This typically indicates corrupted file uploads, unsupported encodings,
 * or malformed PEM/DER byte arrays at the ingestion layer.
 * </p>
 */
public class AuditParsingException extends CertificateAuditException {
    public AuditParsingException(String message) {
        super("Failed to parse X.509 certificate: " + message);
    }

    public AuditParsingException(String message, Throwable cause) {
        super("Failed to parse X.509 certificate: " + message, cause);
    }
}