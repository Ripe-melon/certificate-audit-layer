package com.audit.pki.services.interfaces;

import com.audit.pki.models.Certificate;
import java.util.UUID;

public interface CertificateServiceInterface {

    /**
     * Parses raw certificate bytes, validates basic cryptographic rules 
     * (e.g., expiration, key size), maps to the domain model, and persists the record.
     * * @param rawCertBytes The uploaded .cer or .pem file bytes.
     * @return The fully audited and saved Certificate model.
     */
    Certificate ingestCertificate(byte[] rawCertBytes);

    /**
     * Retrieves a saved certificate by its internal database ID.
     */
    Certificate getCertificateById(UUID id);
}