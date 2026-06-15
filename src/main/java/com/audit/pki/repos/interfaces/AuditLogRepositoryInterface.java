package com.audit.pki.repos.interfaces;

import com.audit.pki.models.AuditLog;
import java.util.List;

public interface AuditLogRepositoryInterface {

    /**
     * Appends a new immutable audit log entry to the database.
     */
    void saveAuditLog(AuditLog log);

    /**
     * Retrieves the entire historical timeline for a specific certificate,
     * ordered from newest to oldest.
     */
    List<AuditLog> getLogsByCertificateId(String certificateId);
}