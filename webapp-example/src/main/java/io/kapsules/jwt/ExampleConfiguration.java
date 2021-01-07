package io.kapsules.jwt;

import com.mongodb.reactivestreams.client.MongoClient;
import com.mongodb.reactivestreams.client.MongoClients;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@Configuration
public class ExampleConfiguration {

  @Value("${db.port:27017}")
  Integer port;

  @Value("${db.server:localhost}")
  String server;

  @Value("${db.name:opa-demo}")
  String dbName;

  @Bean
  PasswordEncoder encoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  /*
   * Use the standard Mongo driver API to create a com.mongodb.client.MongoClient instance.
   */
  public @Bean
  MongoClient mongoClient() {
    return MongoClients.create(String.format("mongodb://%s:%d/%s", server, port, dbName));
  }
}
