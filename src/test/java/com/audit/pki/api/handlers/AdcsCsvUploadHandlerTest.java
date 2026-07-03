package com.audit.pki.api.handlers;

import com.audit.pki.services.implementations.CertificateService;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AdcsCsvUploadHandlerTest {

    private CertificateService mockCertificateService;
    private AdcsCsvUploadHandler handler;
    private HttpExchange mockExchange;
    private Headers requestHeaders;
    private Headers responseHeaders;
    private ByteArrayOutputStream responseStream;

    @BeforeEach
    void setUp() {
        mockCertificateService = mock(CertificateService.class);
        handler = new AdcsCsvUploadHandler(mockCertificateService);
        mockExchange = mock(HttpExchange.class);

        requestHeaders = new Headers();
        responseHeaders = new Headers();
        responseStream = new ByteArrayOutputStream();

        when(mockExchange.getRequestHeaders()).thenReturn(requestHeaders);
        when(mockExchange.getResponseHeaders()).thenReturn(responseHeaders);
        when(mockExchange.getResponseBody()).thenReturn(responseStream);
    }

    @Test
    void testHandle_MethodNotAllowed_WhenNotPostOrOptions() throws IOException {
        // Arrange
        when(mockExchange.getRequestMethod()).thenReturn("GET");

        // Act
        handler.handle(mockExchange);

        // Assert
        verify(mockExchange).sendResponseHeaders(eq(405), anyLong());
        assertTrue(responseStream.toString().contains("Method Not Allowed"));
    }

    @Test
    void testHandle_Unauthorized_WhenMissingApiKey() throws IOException {
        // Arrange
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        // No API key added to headers

        // Act
        handler.handle(mockExchange);

        // Assert
        verify(mockExchange).sendResponseHeaders(eq(401), anyLong());
        assertTrue(responseStream.toString().contains("Unauthorized"));
    }

    @Test
    void testHandle_Success_WithValidMultiLinePem() throws Exception {
        // Arrange
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        requestHeaders.add("X-API-KEY", "audit-pki-super-secret-key-998877");

        // A mock PowerShell ADCS export with a mathematically valid Base64 block
        String mockCsvBody = """
                #TYPE Deserialized.System.Management.Automation.PSCustomObject
                Column1;Column2;Column3
                Metadata Junk;ignore this;
                -----BEGIN CERTIFICATE-----
                VGhpcyBpcyBhIHZhbGlkIG1vY2sgY2VydGlmaWNhdGUg
                c3RyaW5nIGZvciB0ZXN0aW5nIHB1cnBvc2VzLg==
                -----END CERTIFICATE-----
                """;

        InputStream inputStream = new ByteArrayInputStream(mockCsvBody.getBytes(StandardCharsets.UTF_8));
        when(mockExchange.getRequestBody()).thenReturn(inputStream);

        // Act
        handler.handle(mockExchange);

        // Assert
        // 1. Check HTTP response code is 200 OK
        verify(mockExchange).sendResponseHeaders(eq(200), anyLong());

        // 2. Check the JSON response indicates 1 success
        String responseBody = responseStream.toString();
        assertTrue(responseBody.contains("\"success\": 1"), "Expected success count to be 1, but was: " + responseBody);

        // 3. Verify the CertificateService was called exactly once with a cleaned byte
        // array
        ArgumentCaptor<byte[]> byteCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(mockCertificateService, times(1)).ingestCertificate(
                byteCaptor.capture(),
                eq("unknown"),
                eq("unknown"),
                eq("ADCS Bulk Sync"));

        // Ensure the byte array isn't empty
        assertTrue(byteCaptor.getValue().length > 0);
    }
}