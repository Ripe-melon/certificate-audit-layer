package com.audit.pki.api.handlers;

import com.audit.pki.services.implementations.CertificateService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class AdcsCsvUploadHandler implements HttpHandler {

    private static final String VALID_API_KEY = "audit-pki-super-secret-key-998877";
    private final CertificateService certificateService;

    public AdcsCsvUploadHandler(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // Handle CORS preflight
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        // Enforce POST
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            return;
        }

        // Authenticate
        String apiKey = exchange.getRequestHeaders().getFirst("X-API-KEY");
        if (apiKey == null || !apiKey.equals(VALID_API_KEY)) {
            sendResponse(exchange, 401, "{\"error\": \"Unauthorized\"}");
            return;
        }

        int successCount = 0;
        int failureCount = 0;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {

            StringBuilder certBuilder = new StringBuilder();
            boolean inCert = false;

            String line;
            while ((line = reader.readLine()) != null) {
                // Skip empty lines
                if (line.trim().isEmpty())
                    continue;

                // 1. Detect start of certificate block (ignores headers and metadata)
                if (line.contains("-----BEGIN CERTIFICATE-----")) {
                    inCert = true;
                    certBuilder = new StringBuilder();

                    // CRITICAL: Extract only the part AFTER the marker
                    String afterMarker = line.substring(line.indexOf("-----BEGIN CERTIFICATE-----"));
                    certBuilder.append(afterMarker).append("\n");
                    continue; // Skip to next line
                }

                // 2. Accumulate lines if we are inside a certificate block
                if (inCert) {
                    certBuilder.append(line).append("\n");

                    // 3. Detect end of certificate block and process
                    if (line.contains("-----END CERTIFICATE-----")) {
                        inCert = false;
                        try {
                            byte[] cleanCertBytes = decodeMicrosoftPem(certBuilder.toString());

                            // Inside your while loop, where you process the block:
                            if (successCount < 10) {
                                certificateService.ingestCertificate(cleanCertBytes, "unknown",
                                        "unknown", "ADCS Bulk Sync");
                                successCount++;
                            } else {
                                // Stop after 10 to protect the DB while we test
                                break;
                            }
                        } catch (Exception e) {
                            failureCount++;
                        }
                    }
                }

            }

            // 4. Return Summary
            String jsonResponse = String.format("{\"processed\": %d, \"success\": %d, \"failed\": %d}",
                    (successCount + failureCount), successCount, failureCount);

            exchange.getResponseHeaders().add("Content-Type", "application/json");
            sendResponse(exchange, 200, jsonResponse);

        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(exchange, 500, "{\"error\": \"Failed to process stream: " + e.getMessage() + "\"}");
        }
    }
    // --- UTILITY METHODS ---

    private Map<String, Integer> mapHeaders(String headerLine) {
        Map<String, Integer> map = new HashMap<>();
        String[] headers = headerLine.split(";");
        System.out.println("--- DEBUG: CSV Headers Found ---");
        for (int i = 0; i < headers.length; i++) {
            String clean = cleanString(headers[i]);
            map.put(clean, i);
            System.out.println("Column " + i + ": '" + clean + "'");
        }
        return map;
    }

    private String cleanString(String input) {
        return input.replace("\"", "").trim();
    }

    /**
     * Microsoft ADCS exports inject weird characters like _x000D_ (Carriage
     * Returns)
     * This strips all formatting and returns a pure raw byte array.
     */
    private byte[] decodeMicrosoftPem(String rawPem) {
        // 1. Remove markers and common noise
        String cleaned = rawPem
                .replace("\"", "")
                .replace("_x000D_", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "");

        // 2. The Nuclear Option: Remove EVERYTHING that isn't a valid Base64 character
        // Valid Base64 chars are A-Z, a-z, 0-9, +, /, and =
        cleaned = cleaned.replaceAll("[^A-Za-z0-9+/=]", "");

        int padding = cleaned.length() % 4;
        if (padding != 0) {
            cleaned += "=".repeat(4 - padding);
        }

        return Base64.getDecoder().decode(cleaned);
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String responseBody) throws IOException {
        addCorsHeaders(exchange);
        byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, X-API-KEY");
    }
}