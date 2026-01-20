package com.insurai.insurai_backend.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;

/**
 * Database connection test configuration
 * This will test the database connection on application startup
 */
@Configuration
public class DatabaseConnectionTest {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseConnectionTest.class);

    @Bean
    CommandLineRunner testDatabaseConnection(DataSource dataSource) {
        return args -> {
            try (Connection connection = dataSource.getConnection()) {
                if (connection != null && !connection.isClosed()) {
                    logger.info("✅ Database connection successful!");
                    logger.info("📊 Connected to: {}", connection.getCatalog());
                    logger.info("🔗 Database URL: {}", connection.getMetaData().getURL());
                    logger.info("👤 Database User: {}", connection.getMetaData().getUserName());
                } else {
                    logger.error("❌ Database connection failed!");
                }
            } catch (Exception e) {
                logger.error("❌ Error testing database connection: {}", e.getMessage());
                logger.error("💡 Please check:");
                logger.error("   - MySQL service is running");
                logger.error("   - Database 'insurai_db' exists");
                logger.error("   - Environment variables DB_USERNAME and DB_PASSWORD are set");
                logger.error("   - Credentials are correct");
            }
        };
    }
}

