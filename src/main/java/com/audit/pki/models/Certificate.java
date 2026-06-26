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
    private Instant lastAuditedAt;

    private String templateName;
    private String systemOwner;
    private String deploymentMethod;

    /**
     * Standard constructor for creating a NEW certificate in the application.
     * Auto-generates the UUID and defaults status to UNAUDITED and isRevoked to
     * false.
     */
    public Certificate(String serialNumber, String thumbprintSha256, String subjectDn,
            String issuerDn, List<String> subjectAlternativeNames, Instant validFrom,
            Instant validTo, String signatureAlgorithm, String keyAlgorithm,
            int keySize, List<String> extendedKeyUsages, String rawCertificateString,
            String templateName, String systemOwner, String deploymentMethod) { // <-- Added parameters

        this.id = UUID.randomUUID();
        this.serialNumber = serialNumber;
        this.thumbprintSha256 = thumbprintSha256;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.subjectAlternativeNames = new ArrayList<>(subjectAlternativeNames);
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
        this.extendedKeyUsages = new ArrayList<>(extendedKeyUsages);
        this.rawCertificateString = rawCertificateString;

        this.auditStatus = "UNAUDITED";
        this.isRevoked = false;

        // --- NEW ASSIGNMENTS ---
        this.templateName = templateName;
        this.systemOwner = systemOwner;
        this.deploymentMethod = deploymentMethod;
    }

    /**
     * Rehydration constructor used by the Repository to rebuild an EXISTING
     * certificate from PostgreSQL.
     * Takes the explicit ID and Status rather than generating them.
     */
    public Certificate(UUID id, String serialNumber, String thumbprintSha256, String subjectDn,
            String issuerDn, List<String> subjectAlternativeNames, Instant validFrom,
            Instant validTo, String signatureAlgorithm, String keyAlgorithm,
            int keySize, List<String> extendedKeyUsages, boolean isRevoked, String rawCertificateString,
            String auditStatus, Instant lastAuditedAt,
            String templateName, String systemOwner, String deploymentMethod) { // <-- Added parameters

        this.id = id;
        this.serialNumber = serialNumber;
        this.thumbprintSha256 = thumbprintSha256;
        this.subjectDn = subjectDn;
        this.issuerDn = issuerDn;
        this.subjectAlternativeNames = new ArrayList<>(subjectAlternativeNames);
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
        this.extendedKeyUsages = new ArrayList<>(extendedKeyUsages);
        this.isRevoked = isRevoked;
        this.rawCertificateString = rawCertificateString;
        this.auditStatus = auditStatus;
        this.lastAuditedAt = lastAuditedAt;

        // --- NEW ASSIGNMENTS ---
        this.templateName = templateName;
        this.systemOwner = systemOwner;
        this.deploymentMethod = deploymentMethod;
    }

    public Instant getLastAuditedAt() {
        return lastAuditedAt;
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

    public String getTemplateName() {
        return templateName;
    }

    public String getSystemOwner() {
        return systemOwner;
    }

    public String getDeploymentMethod() {
        return deploymentMethod;
    }

    // --- Setters ---
    // Note: A rich domain model usually restricts setters to prevent invalid
    // states.
    // We only expose setters for fields that realistically change post-creation.

    public void setRevoked(boolean revoked) {
        isRevoked = revoked;
    }

    // Allow updating the system owner if they discover it later
    public void setSystemOwner(String systemOwner) {
        this.systemOwner = systemOwner;
    }

    public void setAuditStatus(String auditStatus) {
        this.auditStatus = auditStatus;
    }

    public void setLastAuditedAt(Instant lastAuditedAt) {
        this.lastAuditedAt = lastAuditedAt;
    }
}