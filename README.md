PKI Audit Platform 

An automated, mathematically deterministic platform designed to ingest, parse, and validate X.509 cryptographic certificates to ensure strict compliance with the European Union's NIS2 Directive.

Executive Summary

The NIS2 Directive mandates rigorous cybersecurity hygiene for critical infrastructure, requiring organizations to maintain absolute visibility and cryptographic strength over their digital assets. Manual certificate auditing is error-prone, slow, and non-compliant at scale.

This platform solves that business problem by providing a secure, automated pipeline that ingests X.509 certificates (.pem, .cer), mathematically validates their cryptographic parameters (e.g., RSA key sizes, expiration windows, signature algorithms), and permanently records the compliance status into an immutable, relationally mapped audit log.

Architecture Overview

This project is built with a strict commitment to Domain-Driven Design (DDD) and Clean Architecture. It isolates the core mathematical domain from the infrastructure and network layers, ensuring high testability and resilience.

1. The Core Engine (Java Backend)

API Gateway: A lightweight, native Java HTTP Server implementation that acts as a strict security gateway. It enforces CORS, validates API keys (X-API-KEY), and prevents memory exhaustion (DoS) via strict payload size limiters.

Service Layer: Orchestrates the complex business logic. It handles the parsing of binary data into Java X509Certificate objects and maps them to our secure internal Domain Model.

Validation Engine: A deterministic rules engine (Nis2BaselineValidator) that evaluates certificate parameters against hardcoded cryptographic baselines.

2. The Data Access Layer (PostgreSQL)

Relational Integrity: Utilizes PostgreSQL to ensure absolute data consistency. Employs ON CONFLICT DO UPDATE (Upsert) logic mapped to certificate serial numbers to gracefully handle duplicate uploads.

JSONB Integration: Leverages PostgreSQL's JSONB data types and Google's Gson library to efficiently serialize and store complex, variable-length X.509 extensions (like Subject Alternative Names and Extended Key Usages).

Immutable Auditing: Every evaluation generates a cryptographically tied, append-only record in an audit_logs table, secured by strict Foreign Key constraints.

3. Future Roadmap

The Presentation Layer (React): A planned frontend dashboard to visualize compliance metrics, expiring certificates, and network health.

The AI/RAG Microservice (Python): A planned integration of a Retrieval-Augmented Generation (RAG) microservice. This will allow security analysts to query the structured PostgreSQL audit logs using natural language (e.g., "Which certificates are using non-compliant SHA-1 signatures?").

Running The Application

Prerequisites

Java 21 (or higher)

Maven 3.8+

PostgreSQL 14+

1. Database Setup

Ensure PostgreSQL is running locally. Create the database and user:

CREATE DATABASE pki_audit;
CREATE USER audit_admin WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE pki_audit TO audit_admin;


(Note: Ensure your certificates and audit_logs tables are created as per the Phase 1 schema).

2. Clone the Repository

git clone [https://github.com/your-username/certificate-audit-layer.git](https://github.com/your-username/certificate-audit-layer.git)
cd certificate-audit-layer


3. Run the Test Suite

The core logic and repository boundaries are mathematically verified using JUnit 5 and Mockito.

mvn clean test


4. Build and Run the Application

Start the lightweight HTTP server using the Maven execution plugin:

mvn compile exec:java -Dexec.mainClass="com.audit.pki.Application"


You should see: Server is running on port 8080.

5. Test the API

You can test the ingestion engine using Postman or a simple curl command. Make sure you have a valid cert.pem file in your directory.

Upload a Certificate (POST):

curl -X POST http://localhost:8080/api/v1/certificates/upload \
  -H "X-API-KEY: audit-pki-super-secret-key-998877" \
  --data-binary "@cert.pem"


Retrieve All Certificates (GET):

curl -X GET http://localhost:8080/api/v1/certificates \
  -H "X-API-KEY: audit-pki-super-secret-key-998877"


Built with strict engineering principles for the modern security landscape.