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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

public class CertificateListHandler implements HttpHandler {

    private static final String VALID_API_KEY = "audit-pki-super-secret-key-998877";
    private final CertificateService certificateService;
    private final Gson gson;

    public CertificateListHandler(CertificateService certificateService) {
        this.certificateService = certificateService;
        this.gson = new GsonBuilder()
                .registerTypeAdapter(Instant.class,
                        (JsonSerializer<Instant>) (src, typeOfSrc, context) -> new JsonPrimitive(src.toString()))
                .create();
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // 1. CORS Preflight
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        // 2. Enforce GET method only
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "{\"error\": \"Method Not Allowed\"}");
            return;
        }

        try {
            // 3. Security Bouncer
            String apiKey = exchange.getRequestHeaders().getFirst("X-API-KEY");
            if (apiKey == null || !apiKey.equals(VALID_API_KEY)) {
                sendResponse(exchange, 401, "{\"error\": \"Unauthorized\"}");
                return;
            }

            // 4. Fetch data from the database via the service layer
            List<Certificate> allCertificates = certificateService.getAllCertificates();

            // 5. Convert list to JSON and return
            String jsonResponse = gson.toJson(allCertificates);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            sendResponse(exchange, 200, jsonResponse);

        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(exchange, 500, "{\"error\": \"Internal Server Error\"}");
        }
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
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, X-API-KEY");
    }
}