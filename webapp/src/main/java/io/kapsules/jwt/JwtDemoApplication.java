package io.kapsules.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.mongodb.repository.config.EnableReactiveMongoRepositories;

@SpringBootApplication
@EnableConfigurationProperties
@EnableReactiveMongoRepositories(basePackages = "io.kapsules.jwt")
public class JwtDemoApplication {
  public static void main(String[] args) {
    SpringApplication.run(JwtDemoApplication.class, args);
  }
}
