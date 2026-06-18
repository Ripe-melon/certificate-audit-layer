package com.audit.pki.api.handlers;

import com.audit.pki.models.Certificate;
import com.audit.pki.services.implementations.CertificateService;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class CertificateUploadHandler implements HttpHandler {

    // The single, hardcoded API key for prototype security
    private static final String VALID_API_KEY = "audit-pki-super-secret-key-998877";

    // Threat Defense: Max payload size is 25 KB
    private static final long MAX_PAYLOAD_BYTES = 25 * 1024;

    private final CertificateService certificateService;

    public CertificateUploadHandler(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // 1. Handle CORS Preflight Requests (Required for Phase 5 frontend)
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(204, -1); // 204 No Content
            return;
        }

        // We only accept POST requests for uploads
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "Method Not Allowed. Use POST.");
            return;
        }

        try {
            // 2. Threat Defense: Authentication Bouncer
            String apiKey = exchange.getRequestHeaders().getFirst("X-API-KEY");
            if (apiKey == null || !apiKey.equals(VALID_API_KEY)) {
                System.out.println("Unauthorized attempt blocked.");
                sendResponse(exchange, 401, "Unauthorized: Invalid or missing API Key.");
                return;
            }

            // 3. Threat Defense: Memory Exhaustion Bouncer
            long contentLength = Long.parseLong(exchange.getRequestHeaders().getFirst("Content-Length"));
            if (contentLength > MAX_PAYLOAD_BYTES) {
                System.out.println("Payload too large attempt blocked. Size: " + contentLength);
                sendResponse(exchange, 413, "Payload Too Large: Maximum allowed size is 25 KB.");
                return;
            }

            // 4. Extract the payload and pass to the core engine
            InputStream is = exchange.getRequestBody();
            byte[] rawCertBytes = is.readAllBytes();

            // Call the core logic
            Certificate processedCert = certificateService.ingestCertificate(rawCertBytes);

            Gson gson = new GsonBuilder()
                    .registerTypeAdapter(Instant.class,
                            (JsonSerializer<Instant>) (src, typeOfSrc, context) -> new JsonPrimitive(src.toString())) // Converts
                                                                                                                      // Instant
                                                                                                                      // to
                                                                                                                      // "2026-06-18T15:11:37Z"
                    .create();

            String jsonResponse = gson.toJson(processedCert);

            // Send the JSON back with the proper Content-Type header
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            sendResponse(exchange, 200, jsonResponse);

        } catch (NumberFormatException e) {
            sendResponse(exchange, 411, "Length Required: Must provide Content-Length header.");
        } catch (Exception e) {
            // Catch-all for domain exceptions (like our custom parsing errors)
            e.printStackTrace();
            sendResponse(exchange, 400, "Bad Request: Failed to process certificate. " + e.getMessage());
        }
    }

    // Helper method to write the HTTP response cleanly
    private void sendResponse(HttpExchange exchange, int statusCode, String responseBody) throws IOException {
        addCorsHeaders(exchange);
        byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // Helper method to add Cross-Origin Resource Sharing headers
    private void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*"); // Allow all for prototype
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, X-API-KEY");
    }
}