package com.audit.pki.shared.exceptions;

public class DatabaseOperationException extends CertificateAuditException {

    public DatabaseOperationException(String message) {
        super(message);
    }

    public DatabaseOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}