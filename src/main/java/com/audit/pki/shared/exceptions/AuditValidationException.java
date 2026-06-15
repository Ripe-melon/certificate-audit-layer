package com.audit.pki.shared.exceptions;

public class AuditValidationException extends RuntimeException {
    public AuditValidationException(String message) {
        super(message);
    }

    public AuditValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}