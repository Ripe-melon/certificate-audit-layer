package com.audit.pki.models;

import java.time.Instant;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;

/**
 * Represents a digital certificate with all relevant attributes for auditing.
 * This model is used both for storing in the database and for processing within
 * the application.
 */
public class Certificate {

    private UUID id;
    private String serialNumber;
    private String thumbprintSha256;
    private String subjectDn;
    private String issuerDn;
    private List<String> subjectAlternativeNames;
    private Instant validFrom;
    private Instant validTo;
    private String signatureAlgorithm;
    private String keyAlgorithm;
    private int keySize;
    private List<String> extendedKeyUsages;
    private boolean isRevoked;
    private String rawCertificateString;
    private String auditStatus;

    /**
     * Standard constructor for creating a NEW certificate in the application.
     * Auto-generates the UUID and defaults status to UNAUDITED and isRevoked to
     * false.
     */
    public Certificate(String serialNumber, String thumbprintSha256, String subjectDn,
            String issuerDn, List<String> subjectAlternativeNames, Instant validFrom,
            Instant validTo, String signatureAlgorithm, String keyAlgorithm,
            int keySize, List<String> extendedKeyUsages, String rawCertificateString) {
        this.id = UUID.randomUUID();
        this.serialNumber = serialNumber;
        this.thumbprintSha256 = thumbprintSha256;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        // Creating defensive copies of the lists to prevent external mutability
        this.subjectAlternativeNames = subjectAlternativeNames != null ? new ArrayList<>(subjectAlternativeNames)
                : new ArrayList<>();
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
        this.extendedKeyUsages = extendedKeyUsages != null ? new ArrayList<>(extendedKeyUsages) : new ArrayList<>();
        this.isRevoked = false;
        this.rawCertificateString = rawCertificateString;
        this.auditStatus = "UNAUDITED";
    }

    /**
     * Full constructor for reconstructing an EXISTING certificate from the
     * database.
     */
    public Certificate(UUID id, String serialNumber, String thumbprintSha256, String subjectDn,
            String issuerDn, List<String> subjectAlternativeNames, Instant validFrom,
            Instant validTo, String signatureAlgorithm, String keyAlgorithm,
            int keySize, List<String> extendedKeyUsages, boolean isRevoked,
            String rawCertificateString, String auditStatus) {
        this.id = id;
        this.serialNumber = serialNumber;
        this.thumbprintSha256 = thumbprintSha256;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.subjectAlternativeNames = subjectAlternativeNames != null ? new ArrayList<>(subjectAlternativeNames)
                : new ArrayList<>();
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
        this.extendedKeyUsages = extendedKeyUsages != null ? new ArrayList<>(extendedKeyUsages) : new ArrayList<>();
        this.isRevoked = isRevoked;
        this.rawCertificateString = rawCertificateString;
        this.auditStatus = auditStatus;
    }

    // --- Getters ---
    public UUID getId() {
        return id;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getThumbprintSha256() {
        return thumbprintSha256;
    }

    public String getSubjectDn() {
        return subjectDn;
    }

    public String getIssuerDn() {
        return issuerDn;
    }

    // Returns a defensive copy to protect the internal state
    public List<String> getSubjectAlternativeNames() {
        return new ArrayList<>(subjectAlternativeNames);
    }

    public Instant getValidFrom() {
        return validFrom;
    }

    public Instant getValidTo() {
        return validTo;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public List<String> getExtendedKeyUsages() {
        return new ArrayList<>(extendedKeyUsages);
    }

    public boolean isRevoked() {
        return isRevoked;
    }

    public String getRawCertificateString() {
        return rawCertificateString;
    }

    public String getAuditStatus() {
        return auditStatus;
    }

    // --- Setters ---
    // Note: A rich domain model usually restricts setters to prevent invalid
    // states.
    // We only expose setters for fields that realistically change post-creation.
    public void setRevoked(boolean revoked) {
        isRevoked = revoked;
    }

    public void setAuditStatus(String auditStatus) {
        this.auditStatus = auditStatus;
    }
}