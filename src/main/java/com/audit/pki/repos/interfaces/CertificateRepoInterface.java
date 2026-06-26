package com.audit.pki.repos.interfaces;

import java.util.List;
import java.time.Instant;
import java.util.UUID;

import com.audit.pki.models.Certificate;

public interface CertificateRepoInterface {

     UUID saveCertificate(Certificate certificate);

     Certificate getCertificateById(UUID id);

     Certificate getCertificateBySerialNumber(String serialNumber);

     Certificate getCertificateByThumbprint(String thumbprintSha256);

     boolean existsByThumbprint(String thumbprintSha256);

     List<Certificate> getCertificatesByIssuerDn(String issuerDn);

     List<Certificate> getCertificatesByDomain(String domain);

     List<String> getCertificateExtendedKeyUsage(UUID id);

     List<Certificate> getAllCertificates();

     List<Certificate> getCertificatesByAuditStatus(String auditStatus);

     List<Certificate> getCertificatesExpiringWithinDays(int days);

     List<Certificate> getCertificatesBySystemOwner(String systemOwner);

     int updateCertificate(UUID id, Certificate certificate);

     int deleteCertificate(UUID id);

     void updateAuditState(UUID id, String auditStatus, Instant lastAuditedAt);

}
