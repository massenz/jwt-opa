// Copyright (c) 2022 AlertAvert.com. All rights reserved.
//

package com.alertavert.opa.security.aws;

import com.alertavert.opa.Constants;
import com.alertavert.opa.ExcludeFromCoverageGenerated;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.util.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.WebIdentityTokenFileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;

import java.net.URI;

import static com.alertavert.opa.Constants.AWS_TOKEN_FILE;
import static com.alertavert.opa.Constants.CREDENTIALS_PROVIDER_LOG;


/**
 * <H2>PatientsApplicationConfiguration</H2>
 *
 * <p>System and application configuration goes here.
 *
 * <p>Here we are trying to configure the AWS client, based on
 * whether we auto-detect the Server to be running locally, or on EKS.</p>
 *
 * @author M. Massenzio, 2020-10-06
 */
@Configuration
@Slf4j
@ExcludeFromCoverageGenerated
public class AwsClientConfiguration {

  @Value("${aws.region:}")
  String region;

  @Value("${aws.profile:}")
  String profile;

  @Value("${aws.endpoint:}")
  String endpoint;

  public Region region() {
    return Region.of(region);
  }

  public String awsProfile() {
    return profile;
  }

  /**
   * <p>Instantiates a Client for AWS Secrets Manager service, using a `profile` (whose credentials
   * are stored in {@literal ~/.aws/credentials}) if the {@literal aws.profile} property is set
   * (typically for local runs/tests); otherwise it uses the
   * {@link WebIdentityTokenFileCredentialsProvider Token Provider} which derives the API Token
   * from a file stored in the container at the location pointed at by the env var
   * {@link Constants#AWS_TOKEN_FILE}; the latter is used when running the service in an EKS Container.
   *
   * <p><strong>For the above to work, the STS service SDK must be in the classpath</strong>
   * <pre>
   *   implementation 'software.amazon.awssdk:sts'
   * </pre>
   *
   * @return a Client to access Secrets Manager and retrieve secrets (passwords)
   */
  @Bean @Profile("aws")
  public SecretsManagerClient secretsManagerClient() {
    log.debug("Instantiating the SecretsManager Client for region = {}", region());

    AwsCredentialsProvider provider;
    if (StringUtils.hasText(profile)) {
      log.info(CREDENTIALS_PROVIDER_LOG, "Profile", profile);
      provider = ProfileCredentialsProvider.create(profile);
    } else {
      log.info(CREDENTIALS_PROVIDER_LOG, "Token File", System.getenv(AWS_TOKEN_FILE));
      provider = WebIdentityTokenFileCredentialsProvider.create();
    }

    SecretsManagerClientBuilder builder = SecretsManagerClient.builder()
        .region(region())
        .credentialsProvider(provider);

    // Typically this is overridden in tests, to point to a local Secrets Manager (e.g. using
    // LocalStack, pointing to http://localhost:4566)
    if (StringUtils.hasText(endpoint)) {
      log.info("Using non-default endpoint, uri = {}", endpoint);
      builder.endpointOverride(URI.create(endpoint));
    }
    return builder.build();
  }
}
