
package com.audit.pki.repos.implementations;

import com.audit.pki.repos.interfaces.CertificateRepoInterface;
import com.audit.pki.models.Certificate;
import com.audit.pki.config.Database;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;

public class CertificateRepository implements CertificateRepoInterface {

    private Database db;
    private final Gson gson;;

    public CertificateRepository(Database db) {
        this.db = db;
        this.gson = new GsonBuilder().create();
    }

    @Override
    public void saveCertificate(Certificate certificate) throws SQLException {
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement(
                        "INSERT INTO certificates (id, serial_number, thumbprint_sha256, subject_dn, issuer_dn, san_list, valid_from, valid_to, signature_algorithm, key_algorithm, key_size, extended_key_usage, is_revoked, raw_certificate, audit_status) VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?)")) {

            stmt.setObject(1, certificate.getId());
            stmt.setString(2, certificate.getSerialNumber());
            stmt.setString(3, certificate.getThumbprintSha256());
            stmt.setString(4, certificate.getSubjectDn());
            stmt.setString(5, certificate.getIssuerDn());
            stmt.setString(6, gson.toJson(certificate.getSubjectAlternativeNames()));
            stmt.setTimestamp(7, java.sql.Timestamp.from(certificate.getValidFrom()));
            stmt.setTimestamp(8, java.sql.Timestamp.from(certificate.getValidTo()));
            stmt.setString(9, certificate.getSignatureAlgorithm());
            stmt.setString(10, certificate.getKeyAlgorithm());
            stmt.setInt(11, certificate.getKeySize());
            stmt.setString(12, gson.toJson(certificate.getExtendedKeyUsages()));
            stmt.setBoolean(13, certificate.isRevoked());
            stmt.setString(14, certificate.getRawCertificateString());
            stmt.setString(15, certificate.getAuditStatus());

            stmt.executeUpdate();
        }
    }

    @Override
    public Certificate getCertificateById(String id) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Certificate getCertificateBySerialNumber(String serialNumber) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Certificate getCertificateByThumbprint(String thumbprintSha256) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<String> getCertificateExtendedKeyUsage(String id) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<Certificate> getAllCertificates() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<Certificate> getCertificatesByAuditStatus(String auditStatus) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<Certificate> getCertificatesExpiringWithinDays(int days) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void updateCertificate(Certificate certificate) {
        // TODO Auto-generated method stub

    }

    @Override
    public void deleteCertificate(String id) {
        // TODO Auto-generated method stub

    }

}