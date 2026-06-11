package com.audit.pki.shared.constants;

public enum ExtendedKeyUsageOid {
    SERVER_AUTH("1.3.6.1.5.5.7.3.1", "Server Authentication"),
    CLIENT_AUTH("1.3.6.1.5.5.7.3.2", "Client Authentication"),
    CODE_SIGNING("1.3.6.1.5.5.7.3.3", "Code Signing"),
    EMAIL_PROTECTION("1.3.6.1.5.5.7.3.4", "Email Protection"),
    UNKNOWN("Unknown", "Unknown Usage");

    private final String oid;
    private final String description;

    ExtendedKeyUsageOid(String oid, String description) {
        this.oid = oid;
        this.description = description;
    }

    public String getOid() {
        return oid;
    }

    public String getDescription() {
        return description;
    }

    // The actual "Translator" method
    public static String getDescriptionByOid(String targetOid) {
        for (ExtendedKeyUsageOid usage : values()) {
            if (usage.getOid().equals(targetOid)) {
                return usage.getDescription();
            }
        }
        return "Custom/Unknown OID (" + targetOid + ")";
    }
}