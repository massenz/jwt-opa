# Integrating Open Policy Agent (OPA) with Spring Security Reactive and JSON Web Tokens (JWT)

[![Author](https://img.shields.io/badge/Author-M.%20Massenzio-green)](https://github.com/massenz)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Linux & MacOS](https://img.shields.io/badge/OS-Linux-green)

[![Build & Test](https://github.com/massenz/jwt-opa/actions/workflows/verify.yml/badge.svg)](https://github.com/massenz/jwt-opa/actions/workflows/verify.yml)
[![Release](https://github.com/massenz/jwt-opa/actions/workflows/release.yml/badge.svg?branch=release)](https://github.com/massenz/jwt-opa/actions/workflows/release.yml)

### Copyright & Licensing

**The code is copyright (c) 2021 AlertAvert.com. All rights reserved**<br>
The code is released under the Apache 2.0 License, see `LICENSE` for details.

# Motivation

[Spring Security](https://spring.io/projects/spring-security) assumes a fairly simplistic Role-Based access control (RBAC) where the service authenticates the user (via some credentials, typically username/password) and returns a `UserDetails` object which also lists the `Authorities` that the `Principal` has been granted.

While it is also possible to integrate Spring Security with JSON Web Tokens ([JWT](https://auth0.com/docs/tokens/json-web-tokens)) this is also rather cumbersome, and lacks flexibility.

Finally, integrating the app with an [Open Policy Agent](https://play.openpolicyagent.org/) server for the relatively new [Spring Reactive](https://projectreactor.io/docs/core/release/reference) (`WebFlux`) model is far from straightforward.

Ultimately, however, Spring Security "collapses" authentication and authorization into a single process, based on the `UserDetails` abstraction, which sometimes does not allow sufficient flexibility.

This library aims at simplifying the ability for an application/service to:

- clearly separating **authentication** from **authorization**;
- easily adopt JWTs (API Tokens) as a means of **authentication**;
- simplify integration with OPA for **authorization**;
- keeping the authorization logic (embedded in [Rego](https://www.openpolicyagent.org/docs/latest/policy-reference) policies) separate from the business logic (carried out by the application).

It also provides a blueprint to inject OPA authorization in a Spring Reactive (WebFlux) application.

# Usage

*(aka: Guide for the impatient)*

See either this repository [releases page](https://github.com/massenz/jwt-opa/releases) or [Maven Central](https://search.maven.org/artifact/com.alertavert/jwt-opa) for the most recently available release:

```groovy
ext {
    jwtOpaVersion = '0.9.0'
}
```

Configure your project dependencies to include all necessary Spring libraries (JWT-OPA requires at a minimum `starter-security`) as they are not included in the published artifact, the library itself, and other supporting libraries:

```groovy
dependencies {
    // Spring Framework and Security Dependencies, via Boot Starter Kits.
    implementation 'org.springframework.boot:spring-boot-starter-actuator'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    annotationProcessor "org.springframework.boot:spring-boot-configuration-processor"

    // JWT and Encryption dependencies, needed at runtime.
    implementation 'com.auth0:java-jwt:3.10.3'
    implementation 'org.bouncycastle:bcprov-jdk15on:1.70'

    // JWT-OPA Integration, this library.
    // See: https://search.maven.org/artifact/com.alertavert/jwt-opa
    implementation "com.alertavert:jwt-opa:${jwtOpaVersion}"

    // All other dependencies for your project.
    // For example Spring WebFlux and Spring Data MongoDB:
    implementation 'org.springframework.boot:spring-boot-starter-data-mongodb-reactive'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    // etc...
}
```

For more details, take a look into the `webapp-example` demo project, including how to configure and run tests.

# Architecture

![Architecture](docs/images/arch.png)

To acquire an API Token the client needs to access one of the "authenticated" endpoints (as defined in the `routes.authenticated` list property - see the `RoutesConfiguration` class) and obtain a valid JWT from the `JwtTokenProvider`; an example of how to do this (using a simple Spring Data repository, backed by MongoDB) is in the `/login` controller in the example app (`LoginController`): the `SecurityConfiguration` class is what one would implement in any Spring Application with Spring Security enabled:

```java
@Configuration
@EnableWebFluxSecurity
public class SecurityConfiguration {
  @Bean
  public ReactiveUserDetailsService userDetailsService(ReactiveUsersRepository repository) {
    return username -> {
      return repository.findByUsername(username)
          .map(User::toUserDetails);
    };
  }
}
```

Obviously, instead of accessing a local database, the application could use a `WebClient` to access a remote service to retrieve any details (including an encoded password).

Once the user has been authenticated, we can generate a JWT API Token, and return it to the client:

```java
@GetMapping
Mono<JwtController.ApiToken> login(
    @RequestHeader("Authorization") String credentials
) {
  return usernameFromHeader(credentials)
      .flatMap(repository::findByUsername) // See Note.
      .map(u -> {
        String token = provider.createToken(u.getUsername(), u.roles());
        return new JwtController.ApiToken(u.getUsername(), u.roles(), token);
      })
      .doOnSuccess(apiToken ->
          log.debug("User {} authenticated, API Token generated: {}",
              apiToken.getUsername(), apiToken.getApiToken()));
}
```

<sup>**Note**</sup><sub>As you may notice, we are duplicating the roundtrip to the DB for the `User` data; this may (or may not) be a performance issue, especially on performance-sensitive APIs: an obvious solution would be to use either a co-located cache, or even an in-memory one, with a relatively short TTL.</sub>

### Authorization via Open Policy Agent server

More interestingly, once the client has an API Token, it can be used to authorize any other request: this is done by configuring the `OpaReactiveAuthorizationManager` as a `ReactiveAuthorizationManager` (this is "chained" via the `JwtReactiveAuthorizationManager`) which takes care of validating the API Token.

All of this is done transparently by the `jwt-opa` library, without having to change anything in the actual application.

```java
@Override
public Mono<AuthorizationDecision> check(
    Mono<Authentication> authentication,
    ServerHttpRequest request
) {

  return authentication.map(auth -> {
        return makeRequestBody(auth.getCredentials().toString(), request);
      })
      .flatMap(body -> client.post()
          .accept(MediaType.APPLICATION_JSON)
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue(body)
          .exchange())
      .flatMap(response -> response.bodyToMono(Map.class))
      .map(res -> {
        Object result = res.get("result");
        if (StringUtils.isEmpty(result)) {
          return Mono.error(unauthorized());
        }
        return result.toString();
      })
      .map(o -> Boolean.parseBoolean(o.toString()))
      .map(AuthorizationDecision::new);
}
```
<sup>**Simplified code excerpt, please see the OpaReactiveAuthorizationManager class for the full code**</sup>

the `client` is a Spring `WebClient` configured to connect to the OPA Server as configured via the `OpaServerConfiguration` configuration, which reads the following properties from `application.yaml`:

```yaml
opa:
  server: "localhost:8181"
  policy: kapsules
  rule: allow
```

This will eventually send a `TokenBasedAuthorizationRequestBody` (encoded as JSON) to the following endpoint:

    http(s)://localhost:8181/v1/data/kapsules/allow

Depending on what the `allow` rule maps to, this will eventually grant/deny access to the requested endpoint (given the HTTP Method and, optionally, the request's body content).

There is a relationship between the `policy` endpoint and the Rego `package` in your policy: they **must** match, with dots in the package replaced by slashes in the policy path:

```
# Rego:
package com.alertavert.policies

grant {
  # the policy
}

# application.yaml
opa:
  policy: com/alertavert/policies
  rule: grant
```

See [OPA Policies](#opa-policies) for more details, and the [OPA Documentation](https://www.openpolicyagent.org/docs/latest/policy-reference) for more on Rego and the OPA server API.


# Signing Secrets

## Overview

In order to ensure validity of its contents, a JWT needs to be cryptographically signed and the signature added to its body; see [the JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook) for more details.

`jwt-opa` offers currently two signature methods for JWTs:

* a passphrase (secret), using symmetric encryption which needs to be used for both signing and authenticating the JWT; and

* asymmetric Private/Public keypair (using Elliptic Cryptography) where the private key is used to sign and the public key can be used to validate the JWT.

The advantage of the latter is that the Public key can be distributed, and any service (including others completely unrelated to `jwt-opa`) can validate the API Token.

This is being used, for example, by [Copilot IQ](https://copilotiq.com) to use `jwt-opa` (integrated within its Spring Boot API server) to provide API Token for its Lambda Go functions, where they ask `jwt-opa` to generate trusted API Token, but then authentication can be carried out indipedently by the Lambdas, without ever needing to incur the cost of an additional call to the API server.

This also points to the advantage of using OPA as an authorization service, which can serve several disparate other services, completely abstracting away the authorization logic.

## Secrets Configuration

Key configuration is done via Spring Boot externalized configuration (e.g., in [`application.yaml`](https://github.com/massenz/jwt-opa/blob/main/webapp-example/src/main/resources/application.yaml#L81-L104)) via the `keys` object; this in turn has the following fields:

```yaml
keys:
  algorithm: EC
  location: keypair
  name: /var/local/keys/ec-key
```

Possible values for `algorithm` are:

- `PASSPHRASE`:  plaintext secret
- `EC`: Elliptic Curve cryptography key pair

Depending on the value of `location` the `name` property has a different meaning:

- only available for `PASSPHRASE`
  - `env`<br/> env var name which contains the signing secret
  - `file`<br/> the path to file whose contents are the plaintext secret this is **NOT** secure and should only be used for dev/testing


- only available for `EC`
  - `keypair`<br/> the relative or absolute path to the keypair, without extension, to which `.pem` and `.pub` will be added


- either of `EC` or `PASSPHRASE`:
  - `awssecret`<br/> name of AWS SecretsManager secret
  - `vaultpath`<br/> path in HashiCorp Vault (**not implemented yet**)

In the above, file paths can be absolute or relative (in production use, we recommend full absolute paths to avoid hard-to-debug issues - at any rate, the error message should be sufficient to locate the source of the issue).

When using `aswsecret`, a `PASSPHRASE` is simply read from SecretsManager/Vault as plaintext, while for an `EC` `KeyPair` it is stored as a JSON-formatted secret, with two keys: `priv` and `pub` (see [AWS SecretsManager support](#aws-secretsmanager-support)).


## Generating a `KeyPair`

Use the `keygen.sh` script, specifying the name of the keys and, optionally, a folder where to save the keys (if the folder doesn't exist it will be created):

    $ ./keygen.sh  ec-key private

See [this](https://github.com/auth0/java-jwt/issues/270) for more details.

Make sure the keys are in a **private** folder (not under source control) and then point the relevant application configuration (`application.yaml`) to them:

```yaml
keys:
  algorithm: ec
  location: keypair
  name: "private/ec-key"
```

You can use either an absolute path, or the relative path to the current directory from where you are launching the Web server, and make sure to includ the keys' filename, but **not** the extension(s) (`.pem` and `.pub`) as the `KeypairFileReader` will add them automatically.

## AWS SecretsManager support

**This is the recommended secure way to store and access signing secrets**

We support storing signing secrets (both plaintext passphrase or a private/public key pair) in [AWS SecretsManager](https://aws.amazon.com/secrets-manager) by simply configuring access to AWS:

```yaml
aws:
  region: us-west-2
  profile: my-profile
```

the `profile` must match one of those configured in the `~/.aws/credentials` file:

```
# my-profile
[my-profile]
aws_access_key_id = AJIA2....XT
aws_secret_access_key = 22Y8...YM
```

we also support direct acces to SM via IAM Roles when `jwt-opa` is embedded in a service running on AWS (e.g., as a pod in [Amazon Kubernetes](https://aws.amazon.com/eks/)) via a Token file whose name is stored in the `AWS_TOKEN_FILE` env var (see the documentation for AWS SDK's `WebIdentityTokenFileCredentialsProvider`) -- in this case you should **not** specify a `aws.profile` or the client will fail to authenticate.

We also support connecting to a running instance of [LocalStack](https://localstack.io) via the `endpoint_url` configuration:

```
aws:
  region: us-west-2
  profile: default
  endpoint: http://localhost:4566
```

Run LocalStack via docker with something like (this is a `compose.yaml` fragment, YMMV):

```
  19   │   localstack:
  20   │     container_name: "awslocal"
  21   │     image: "localstack/localstack:1.3"
  22   │     hostname: awslocal
  23   │     environment:
  24   │       - AWS_REGION=us-west-2
  25   │       - EDGE_PORT=4566
  26   │       - SERVICES=sqs
  27   │     ports:
  28   │       - '4566:4566'
  29   │     volumes:
  30   │       - "${TMPDIR:-/tmp}/localstack:/var/lib/localstack"
  31   │       - "/var/run/docker.sock:/var/run/docker.sock"
  32   │     networks:
  33   │       - sm-net
```

Prior to running the webapp, upload the secret with:

```
     export AWS_REGION=us-west-2
     export AWS_ENDPOINT=http://localhost:4566
     aws --endpoint-url $AWS_ENDPOINT secretsmanager create-secret --name demo-secret \
         --secret-string "astrong-secret-dce44st"
```

To upload a keypair to AWS SM, the easiest way is to use the `aws-upload-keys` script, after having set the `AWS_PROFILE` env var and generated the keys:

```
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1
./keygen.sh dev-keys testdata
./aws-upload-keys.sh testdata/dev-keys dev-keypair
```

these can then be made available to the application via the following `application.yaml` configuration:

```yaml
aws:
  region: us-east-1
  profile: my-profile

keys:
  algorithm: EC
  location: awssecret
  name: dev-keypair
```

*Key Format*<br/>
While not relevant for library users, the KeyPair is stored in SM as a JSON object, with two `pub` and `priv` fields, which are the contents of the keys (base-64 encoded binary) without delimiters:

```
└─( aws --output json secretsmanager list-secrets \
    | jq -r ".SecretList[].Name" | grep dev

└─( echo -e $(aws --output json secretsmanager get-secret-value \
    --secret-id dev-keypair | jq -r .SecretString)

{ "priv": "AMB....Pi/88", "pub": "MF....v+A==" }
```


## Hashicorp Vault support

**This is not implemented yet**, see [Issue #49](https://github.com/massenz/jwt-opa/issues/49).


# Running the Server

## Supporting Services

The sample app (`webapp-example`) uses the following services:

  - Mongo (users DB);
  - OPA Policy Server

Use the following to run the servers locally:

```
./run-example.sh
```

You can also optionally pass in a value for the Spring Boot profile to use (and relative configuration to use, if defined):

```
./run-example.sh debug,dev

2023-01-07 15:07:37.015  INFO : Starting JwtDemoApplication using Java 17 on gondor with PID 363820
2023-01-07 15:07:37.017  INFO : The following profiles are active: debug,dev
...
```

The service will continue running after you stop the server via Ctrl-C (as you may want to re-run it via `./gradlew bootRun`): to stop the `opa` and `mongo` containers too, simply use:

    docker compose down

from the same directory as the `compose.yaml` is stored, or point to it via the `-f` option.


`TODO:` a Helm chart to run *all* services on a Kubernetes cluster.


## Web Server (Demo app)

This is a very simple Spring Boot application, to demonstrate how to integrate the `jwt-opa` library; there is still some work to refine it, but by and large, it gives a good sense of what is required to integrate a Spring Boot app with an OPA server:

1. implement a `SecurityConfiguration` `@Configuration` class;
2. implement a mechanism to retrieve `UserDetails` given a `username`; and
3. implement something similar to the `LoginController` to serve API Tokens to authenticated users.

In future releases of the `jwt-opa` library we may also provide "default" implementations of some or all of the above, if this can be done without limiting too much client's options; or maybe they could be provided in a `jwt-opa-starter` extension library.

`TODO:` there are stil a few rough edges in the demo app and its APIs.


### Trying out the demo


> **NOTE**
>
> As this is a toy demo, we happily store the password in a source-controlled configuration file: you should easily realize that **this is an extremely dumb thing to do**, please don't do it.

The `admin` password is stored in `application.yaml`:

```
db:
  server: localhost
  port: 27017
  name: opa-demo-db

  # Obviously, well, DON'T DO THIS for a real server.
  admin:
    username: admin
    password: 8535b9c4-a
```


**Note**
> The system user does not get re-created, if it already exists: if you change (and then forget) the password, you will need to manually delete it from Mongo directly:

```
docker exec -it mongo mongo
> show dbs;
...
opa-demo-db  0.000GB
> use opa-demo-db
> db.users.find()
{ "_id" : ObjectId("5ff8173b20953c451f10a384"), "username" : "admin", ...
> db.users.remove(ObjectId("5ff81..."))
```
> and then restart the server to recreate the admin user.
> Alternatively, just stop & restart the Mongo container (but all data will be lost).

To access the `/login` endpoint, you will need to use `Basic` authentication:

    $ http :8080/login --auth admin:342dfa7b-4

this will generate a new API Token, that can then be used in subsequent HTTP API calls, with the `Authorization` header:

    http :8080/users Authorization:"Bearer ... JWT goes here ..."


# OPA Policies

They are stored in `src/main/rego` and can be uploaded to the OPA policy server via a `curl POST` (see `REST API` in [Useful Links](useful-links#)); examples of policy evaulations are in `src/test/policies_tests` as JSON files; they can be executed against the policy server using the `/data` endpoint:


    POST http://localhost:8181/v1/data/com/alertavert/userauth/allow

    {
      "input" : {
        "api_token" : "eyJ0eX****e9ZuZA",
        "resource" : {
          "method" : "GET",
          "path" : "/users",
        }
      }
    }

The actual format of the request POSTed to OPA can be seen in the Debug logs of the server:

```
2023-01-07 15:21:29.335 DEBUG : POST Authorization request:
{
  "input" : {
    "api_token" : "eyJ0eX****e9ZuZA",
    "resource" : {
      "method" : "GET",
      "path" : "/users",
      "headers" : {
        "User-Agent" : "PostmanRuntime/7.30.0",
        "Host" : "localhost:8081",
        "Accept-Encoding" : "gzip, deflate, br"
      }
    }
  }
}
2023-01-07 15:21:29.458 DEBUG : OPA Server returned: {result=true}
2023-01-07 15:21:29.458 DEBUG : JWT Auth Web Filter :: GET /users
2023-01-07 15:21:29.458 DEBUG : Authenticating token eyJ0eX...
2023-01-07 15:21:29.462 DEBUG : API Token valid: sub = `admin`, authorities = [SYSTEM]
2023-01-07 15:21:29.462 DEBUG : Validated API Token for Principal: `admin`
2023-01-07 15:21:29.462 DEBUG : Auth success, principal = `JwtPrincipal(sub=admin)`
```


### Useful links

1. [REGO Playground](https://play.openpolicyagent.org/)
1. [OPA Server REST API for Data](https://www.openpolicyagent.org/docs/latest/rest-api/#data-api)
1. [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
1. [OPA - How does it work](https://www.openpolicyagent.org/docs/latest/philosophy/#how-does-opa-work)
1. [OPA Policy Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
1. [Docker Hub - OPA image](https://hub.docker.com/r/openpolicyagent/opa)
