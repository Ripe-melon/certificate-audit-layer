package com.audit.pki;

import com.audit.pki.api.server.PkiHttpServer;
import com.audit.pki.repos.implementations.AuditLogRepository;
import com.audit.pki.repos.implementations.CertificateRepository;
import com.audit.pki.config.DatabaseConnectionManager;
import com.audit.pki.services.implementations.CertificateService;
import com.audit.pki.services.implementations.Nis2BaselineValidator;

public class Application {
    public static void main(String[] args) {
        System.out.println("Starting PKI Audit Platform...");

        try {
            // 1. Initialize the Database Connection
            // Adjust the credentials/URL parameters here based on your specific
            // implementation
            DatabaseConnectionManager dbManager = new DatabaseConnectionManager(
                    "jdbc:postgresql://localhost:5432/pki_audit",
                    "audit_admin",
                    "secure_password");

            // 2. Initialize Repositories (Data Access Layer)
            CertificateRepository certificateRepo = new CertificateRepository(dbManager);
            AuditLogRepository auditLogRepo = new AuditLogRepository(dbManager);

            // 3. Initialize Business Logic (Service Layer)
            Nis2BaselineValidator validator = new Nis2BaselineValidator();

            // Now fully injecting BOTH repositories and the validator
            CertificateService certificateService = new CertificateService(
                    certificateRepo,
                    auditLogRepo,
                    validator);

            // 4. Start the HTTP Server (API Layer)
            PkiHttpServer server = new PkiHttpServer(8080, certificateService);
            server.start();

            System.out.println("Server is running on port 8080.");

        } catch (Exception e) {
            System.err.println("Fatal error starting the application: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}