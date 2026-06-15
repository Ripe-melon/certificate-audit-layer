package com.audit.pki.repos.implementations;

import com.audit.pki.config.DatabaseConnectionManager;
import com.audit.pki.models.AuditLog;
import com.audit.pki.repos.interfaces.AuditLogRepositoryInterface;
import com.audit.pki.shared.exceptions.DatabaseOperationException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class AuditLogRepository implements AuditLogRepositoryInterface {

    private final DatabaseConnectionManager db;

    public AuditLogRepository(DatabaseConnectionManager db) {
        this.db = db;
    }

    @Override
    public void saveAuditLog(AuditLog log) {
        String sql = "INSERT INTO audit_logs (log_id, certificate_id, timestamp, status_result, details) VALUES (?, ?, ?, ?, ?::jsonb)";

        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setObject(1, log.getLogId());
            stmt.setObject(2, UUID.fromString(log.getCertificateId()));
            stmt.setTimestamp(3, java.sql.Timestamp.from(log.getTimestamp()));
            stmt.setString(4, log.getStatusResult());
            stmt.setString(5, log.getDetails());

            stmt.executeUpdate();

        } catch (SQLException e) {
            throw new DatabaseOperationException(
                    "Failed to save audit log for certificate: " + log.getCertificateId(), e);
        }
    }

    @Override
    public List<AuditLog> getLogsByCertificateId(String certificateId) {
        List<AuditLog> logs = new ArrayList<>();
        // Notice the ORDER BY clause: This ensures the AI or Frontend always sees the
        // most recent events first.
        String sql = "SELECT * FROM audit_logs WHERE certificate_id = ? ORDER BY timestamp DESC";

        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setObject(1, UUID.fromString(certificateId));

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    logs.add(mapRowToAuditLog(rs));
                }
            }
        } catch (SQLException e) {
            throw new DatabaseOperationException(
                    "Failed to retrieve audit logs for certificate: " + certificateId, e);
        }
        return logs;
    }

    // Helper method to keep the code clean and isolated
    private AuditLog mapRowToAuditLog(ResultSet rs) throws SQLException {
        UUID logId = rs.getObject("log_id", UUID.class);
        String certId = rs.getObject("certificate_id", UUID.class).toString();
        Instant timestamp = rs.getTimestamp("timestamp").toInstant();
        String statusResult = rs.getString("status_result");
        String details = rs.getString("details");

        return new AuditLog(logId, certId, timestamp, statusResult, details);
    }
}