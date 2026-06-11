package com.audit.pki.shared.utils;

import com.audit.pki.shared.exceptions.CertificateParsingException;
import com.audit.pki.shared.exceptions.CertificateValidationException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CertificateExtractor {

    /**
     * Extracts a list of Subject Alternative Names (SANs) from the certificate.
     * Currently, this only extracts standard DNS names (type 2).
     * * @param cert The native X509Certificate to parse.
     * 
     * @return A list of extracted domain names, or an empty list if none exist.
     * @throws CertificateParsingException If the SANs cannot be parsed from the
     *                                     certificate.
     */
    public static List<String> extractSanList(X509Certificate cert) {
        List<String> sanList = new ArrayList<>();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();

            // Certificates without SAN extensions will return null
            if (sans != null) {
                for (List<?> sanEntry : sans) {
                    Integer type = (Integer) sanEntry.get(0);

                    // Type '2' represents standard DNS Names
                    // TODO: Expand extraction to handle IP addresses (type 7) and Email addresses
                    // (type 1) later.
                    if (type != null && type == 2) {
                        String domainName = (String) sanEntry.get(1);
                        sanList.add(domainName);
                    }
                }
            }
        } catch (java.security.cert.CertificateParsingException e) {
            throw new CertificateParsingException("Failed to parse SANs from certificate.", e);
        }
        return sanList;
    }

    /**
     * Computes the SHA-256 thumbprint (fingerprint) of the certificate.
     * The thumbprint is a deterministic hash of the raw binary certificate data,
     * used as a globally unique identifier to ensure data integrity.
     *
     * @param certBytes The raw, encoded bytes of the certificate.
     * @return A 64-character, lowercase hexadecimal string representing the hash.
     * @throws CertificateValidationException If the JVM does not support the
     *                                        SHA-256 algorithm.
     */
    public static String calculateSha256Thumbprint(byte[] certBytes) {
        try {
            // Initialize the native Java hashing engine specifically for SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Perform the cryptographic hash on the raw byte array
            byte[] hashBytes = digest.digest(certBytes);

            // Convert the resulting raw bytes into a readable 64-character hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                // "%02x" forces each byte to be represented as 2 lowercase hex digits
                hexString.append(String.format("%02x", b));
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            // Wrap the native checked exception in our custom domain exception
            throw new CertificateValidationException("Invalid Algorithm: SHA-256 is not supported.");
        }
    }

    /**
     * Determines the mathematical bit length (size) of the given public key.
     * Currently, this prototype strictly enforces RSA keys for enterprise
     * compliance.
     *
     * @param publicKey The generic native PublicKey extracted from the certificate.
     * @return The key size in bits (e.g., 2048, 4096).
     * @throws CertificateValidationException If the key is not an RSA key (e.g.,
     *                                        Elliptic Curve).
     */
    public static int getKeySize(PublicKey publicKey) {
        // Use modern Java pattern matching to safely check the type and cast in one
        // step
        if (publicKey instanceof RSAPublicKey rsaKey) {
            // The physical size of an RSA key is the bit length of its mathematical modulus
            return rsaKey.getModulus().bitLength();
        } else {
            // Fail gracefully but loudly if an unsupported key type (like EC) is
            // encountered
            throw new CertificateValidationException(
                    "Unsupported key type: " + publicKey.getAlgorithm() + ". Only RSA is currently supported.");
        }
    }

    /**
     * Extracts the Extended Key Usages (EKUs) from the certificate.
     * EKUs define the approved purposes for the certificate (e.g., Server
     * Authentication).
     * Note: This returns raw Object Identifiers (OIDs), such as
     * "1.3.6.1.5.5.7.3.1".
     *
     * @param cert The native X509Certificate to parse.
     * @return A list of EKU OID strings, or an empty list if no extension is
     *         present.
     * @throws CertificateParsingException If the EKU extension cannot be parsed.
     */
    public static List<String> extractExtendedKeyUsages(X509Certificate cert) {
        try {
            // The native method returns a List of OID strings directly
            List<String> ekus = cert.getExtendedKeyUsage();

            // If the certificate lacks this specific extension, Java returns null.
            // We return an empty list to ensure safe database insertion.
            if (ekus == null) {
                return new ArrayList<>();
            }

            // Return a defensive copy to prevent external mutation of the extracted list
            return new ArrayList<>(ekus);

        } catch (java.security.cert.CertificateParsingException e) {
            throw new CertificateParsingException("Failed to parse Extended Key Usages from certificate.", e);
        }
    }
}