package com.audit.pki.repos.interfaces;

import java.util.List;

import com.audit.pki.models.Certificate;

public interface CertificateRepoInterface {

     void saveCertificate(Certificate certificate) throws Exception;

     Certificate getCertificateById(String id) throws Exception;

     Certificate getCertificateBySerialNumber(String serialNumber) throws Exception;

     Certificate getCertificateByThumbprint(String thumbprintSha256) throws Exception;

     boolean existsByThumbprint(String thumbprintSha256) throws Exception;

     List<Certificate> getCertificatesByIssuerDn(String issuerDn) throws Exception;

     List<Certificate> getCertificatesByDomain(String domain) throws Exception;

     List<String> getCertificateExtendedKeyUsage(String id) throws Exception;

     List<Certificate> getAllCertificates() throws Exception;

     List<Certificate> getCertificatesByAuditStatus(String auditStatus) throws Exception;

     List<Certificate> getCertificatesExpiringWithinDays(int days) throws Exception;

     int updateCertificate(String id, Certificate certificate) throws Exception;

     int deleteCertificate(String id) throws Exception;

}
