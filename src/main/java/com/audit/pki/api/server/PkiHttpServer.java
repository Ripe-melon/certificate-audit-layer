package com.audit.pki.api.server;

import com.audit.pki.api.handlers.CertificateListHandler;
import com.audit.pki.api.handlers.CertificateUploadHandler;
import com.audit.pki.services.implementations.CertificateService;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;

public class PkiHttpServer {
    private final int port;
    private final CertificateService certificateService;
    private HttpServer server;

    public PkiHttpServer(int port, CertificateService certificateService) {
        this.port = port;
        this.certificateService = certificateService;
    }

    public void start() throws IOException {
        // Create the server binding to the specified port
        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Map the URL path to our specific handler, passing the core service
        server.createContext("/api/v1/certificates/upload", new CertificateUploadHandler(certificateService));
        server.createContext("/api/v1/certificates", new CertificateListHandler(certificateService));

        // Use the default executor
        server.setExecutor(null);
        server.start();

        System.out.println("PkiHttpServer started and listening on port " + port);
    }

    public void stop() {
        if (server != null) {
            // Stop immediately (0 seconds delay)
            server.stop(0);
            System.out.println("PkiHttpServer stopped.");
        }
    }
}