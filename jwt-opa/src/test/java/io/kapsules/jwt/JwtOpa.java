package io.kapsules.jwt;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Profile;

/**
 * Simple marker class to hold Spring Boot annotations.
 */
@Profile("test")
@SpringBootApplication
public class JwtOpa {
}
