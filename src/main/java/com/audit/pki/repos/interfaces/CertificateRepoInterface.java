package com.audit.pki.repos.interfaces;

import java.util.List;

import com.audit.pki.models.Certificate;

public interface CertificateRepoInterface {

     void saveCertificate(Certificate certificate) throws Exception;

     Certificate getCertificateById(String id);

     Certificate getCertificateBySerialNumber(String serialNumber);

     Certificate getCertificateByThumbprint(String thumbprintSha256);

     List<String> getCertificateExtendedKeyUsage(String id);

     List<Certificate> getAllCertificates();

     List<Certificate> getCertificatesByAuditStatus(String auditStatus);

     List<Certificate> getCertificatesExpiringWithinDays(int days);

     void updateCertificate(Certificate certificate);

     void deleteCertificate(String id);

}
