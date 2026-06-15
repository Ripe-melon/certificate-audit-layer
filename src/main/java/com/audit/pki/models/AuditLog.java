package com.audit.pki.models;

import java.time.Instant;
import java.util.UUID;

public class AuditLog {

    private final UUID logId;
    private final String certificateId; // Foreign key
    private final Instant timestamp;
    private final String statusResult;
    private final String details; // Stored as a JSON String for PostgreSQL JSONB

    /**
     * Constructor for reconstructing an EXISTING log from the database.
     */
    public AuditLog(UUID logId, String certificateId, Instant timestamp, String statusResult, String details) {
        this.logId = logId;
        this.certificateId = certificateId;
        this.timestamp = timestamp;
        this.statusResult = statusResult;
        this.details = details;
    }

    /**
     * Constructor for creating a NEW log event in the application.
     * Auto-generates the logId and locks in the current timestamp.
     */
    public AuditLog(String certificateId, String statusResult, String details) {
        this.logId = UUID.randomUUID();
        this.certificateId = certificateId;
        this.timestamp = Instant.now();
        this.statusResult = statusResult;
        this.details = details;
    }

    public UUID getLogId() {
        return logId;
    }

    public String getCertificateId() {
        return certificateId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getStatusResult() {
        return statusResult;
    }

    public String getDetails() {
        return details;
    }
}