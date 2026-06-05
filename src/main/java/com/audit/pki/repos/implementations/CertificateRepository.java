
package com.audit.pki.repos.implementations;

import com.audit.pki.repos.interfaces.CertificateRepoInterface;
import com.audit.pki.models.Certificate;
import com.audit.pki.config.DatabaseConnectionManager;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import java.time.Instant;
import java.util.ArrayList;
import java.lang.reflect.Type;

/**
 * Implementation of CertificateRepoInterface using JDBC to interact with a
 * PostgreSQL database.
 * This class handles all CRUD operations for Certificate entities, including
 * saving new certificates,
 * retrieving certificates by various attributes, and updating or deleting
 * certificates as needed.
 * It uses Gson to serialize and deserialize complex fields like lists into JSON
 * format for storage in the database.
 */
public class CertificateRepository implements CertificateRepoInterface {

    private DatabaseConnectionManager db;
    private final Gson gson;
    private final Type listType;

    public CertificateRepository(DatabaseConnectionManager db) {
        this.db = db;
        this.gson = new GsonBuilder().create();
        this.listType = new TypeToken<ArrayList<String>>() {
        }.getType();

    }

    /**
     * Saves a new certificate to the database.
     */
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
    public Certificate getCertificateById(String id) throws SQLException {
        Certificate cert = null;
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement("SELECT * FROM certificates WHERE id = ?")) {
            stmt.setObject(1, UUID.fromString(id));
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    cert = mapRowToCertificate(rs);
                }
            }
        }
        return cert;
    }

    @Override
    public Certificate getCertificateBySerialNumber(String serialNumber) throws SQLException {
        Certificate cert = null;
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement("SELECT * FROM certificates WHERE serial_number = ?")) {
            stmt.setString(1, serialNumber);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    cert = mapRowToCertificate(rs);
                }
            }
        }
        return cert;
    }

    @Override
    public Certificate getCertificateByThumbprint(String thumbprintSha256) throws SQLException {
        Certificate cert = null;
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn
                        .prepareStatement("SELECT * FROM certificates WHERE thumbprint_sha256 = ?")) {
            stmt.setString(1, thumbprintSha256);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    cert = mapRowToCertificate(rs);
                }
            }
        }
        return cert;
    }

    @Override
    public boolean existsByThumbprint(String thumbprintSha256) throws SQLException {
        boolean exists = false;
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn
                        .prepareStatement("SELECT EXISTS(SELECT 1 FROM certificates WHERE thumbprint_sha256 = ?)")) {
            stmt.setString(1, thumbprintSha256);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    exists = rs.getBoolean(1);
                }
            }
        }
        return exists;
    }

    @Override
    public List<Certificate> getCertificatesByIssuerDn(String issuerDn) throws SQLException {
        List<Certificate> certificates = new ArrayList<>();
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement("SELECT * FROM certificates WHERE issuer_dn = ?")) {
            stmt.setString(1, issuerDn);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    certificates.add(mapRowToCertificate(rs));
                }
            }
        }
        return certificates;
    }

    @Override
    public List<Certificate> getCertificatesByDomain(String domain) throws SQLException {
        List<Certificate> certificates = new ArrayList<>();
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement(
                        "SELECT * FROM certificates WHERE san_list::jsonb @> ?::jsonb")) {
            String domainJson = "[\"" + domain + "\"]";
            stmt.setString(1, domainJson);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    certificates.add(mapRowToCertificate(rs));
                }
            }
        }
        return certificates;
    }

    @Override
    public List<String> getCertificateExtendedKeyUsage(String id) throws SQLException {
        List<String> extendedKeyUsages = new ArrayList<>();
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn
                        .prepareStatement("SELECT extended_key_usage FROM certificates WHERE id = ?")) {
            stmt.setObject(1, UUID.fromString(id));
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    extendedKeyUsages.addAll(gson.fromJson(rs.getString("extended_key_usage"), listType));
                }
            }
        }
        return extendedKeyUsages;
    }

    @Override
    public List<Certificate> getAllCertificates() throws SQLException {
        List<Certificate> certificates = new ArrayList<>();
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement("SELECT * FROM certificates");) {
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    certificates.add(mapRowToCertificate(rs));
                }
            }
        }

        return certificates;
    }

    @Override
    public List<Certificate> getCertificatesByAuditStatus(String auditStatus) {
        List<Certificate> certificates = new ArrayList<>();
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement("SELECT * FROM certificates WHERE audit_status = ?")) {
            stmt.setString(1, auditStatus);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    certificates.add(mapRowToCertificate(rs));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return certificates;
    }

    @Override
    public List<Certificate> getCertificatesExpiringWithinDays(int days) {
        List<Certificate> certificates = new ArrayList<>();
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement(
                        "SELECT * FROM certificates WHERE valid_to <= CURRENT_TIMESTAMP + (? * INTERVAL '1 DAY')")) {
            stmt.setInt(1, days);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    certificates.add(mapRowToCertificate(rs));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return certificates;
    }

    @Override
    public int updateCertificate(String id, Certificate certificate) throws SQLException {
        int rowsAffected = 0;
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement(
                        "UPDATE certificates SET is_revoked = ?, audit_status = ? WHERE id = ? ")) {
            stmt.setBoolean(1, certificate.isRevoked());
            stmt.setString(2, certificate.getAuditStatus());
            stmt.setObject(3, UUID.fromString(id));

            rowsAffected = stmt.executeUpdate();
        }
        return rowsAffected;
    }

    @Override
    public int deleteCertificate(String id) throws SQLException {
        int rowsAffected = 0;
        try (Connection conn = db.getConnection();
                PreparedStatement stmt = conn.prepareStatement("DELETE FROM certificates WHERE id = ?")) {
            stmt.setObject(1, UUID.fromString(id));
            rowsAffected = stmt.executeUpdate();
        }
        return rowsAffected;
    }

    // Helper method to map a ResultSet row to a Certificate object
    private Certificate mapRowToCertificate(ResultSet rs) throws SQLException {

        UUID id = rs.getObject("id", UUID.class);
        String serialNumber = rs.getString("serial_number");
        String thumbprintSha256 = rs.getString("thumbprint_sha256");
        String subjectDn = rs.getString("subject_dn");
        String issuerDn = rs.getString("issuer_dn");
        List<String> sanList = gson.fromJson(rs.getString("san_list"), listType);
        Instant validFrom = rs.getTimestamp("valid_from").toInstant();
        Instant validTo = rs.getTimestamp("valid_to").toInstant();
        String signatureAlgorithm = rs.getString("signature_algorithm");
        String keyAlgorithm = rs.getString("key_algorithm");
        int keySize = rs.getInt("key_size");
        List<String> extendedKeyUsage = gson.fromJson(rs.getString("extended_key_usage"), listType);
        boolean isRevoked = rs.getBoolean("is_revoked");
        String rawCertificateString = rs.getString("raw_certificate");
        String auditStatus = rs.getString("audit_status");

        return new Certificate(id, serialNumber, thumbprintSha256, subjectDn, issuerDn, sanList, validFrom, validTo,
                signatureAlgorithm, keyAlgorithm, keySize, extendedKeyUsage, isRevoked, rawCertificateString,
                auditStatus);
    }

}