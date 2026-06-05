package com.audit.pki.config.interfaces;

import java.sql.Connection;

public interface Database {
    Connection getConnection();
}