package com.audit.pki.repos.interfaces;

import java.util.List;
import java.time.Instant;

import com.audit.pki.models.Certificate;

public interface CertificateRepoInterface {

     void saveCertificate(Certificate certificate);

     Certificate getCertificateById(String id);

     Certificate getCertificateBySerialNumber(String serialNumber);

     Certificate getCertificateByThumbprint(String thumbprintSha256);

     boolean existsByThumbprint(String thumbprintSha256);

     List<Certificate> getCertificatesByIssuerDn(String issuerDn);

     List<Certificate> getCertificatesByDomain(String domain);

     List<String> getCertificateExtendedKeyUsage(String id);

     List<Certificate> getAllCertificates();

     List<Certificate> getCertificatesByAuditStatus(String auditStatus);

     List<Certificate> getCertificatesExpiringWithinDays(int days);

     int updateCertificate(String id, Certificate certificate);

     int deleteCertificate(String id);

     void updateAuditState(String id, String auditStatus, Instant lastAuditedAt);

}
