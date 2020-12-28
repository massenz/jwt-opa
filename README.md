# JWT Integration with OPA, Using Spring Security

![Version](https://img.shields.io/badge/Version-0.1.0-blue)
![Released](https://img.shields.io/badge/Released-2020.12.11-green)

[![Author](https://img.shields.io/badge/Author-M.%20Massenzio-green)](https://bitbucket.org/marco)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![OS Debian](https://img.shields.io/badge/OS-Linux-green)

# Motivation


# Architecture

```TODO```

# Running

## Generating a `KeyPair`

Use the `keygen.sh` script, specifying the name of the keys and, optionally, a folder where to save the keys (the folder **must** exist):

    $ ./keygen.sh  ec-key private

See [this](https://github.com/auth0/java-jwt/issues/270) for more details.

Briefly, an "elliptic cryptography" key pair can be generated with:

1. generate the EC param

        openssl ecparam -name prime256v1 -genkey -noout -out ec-key.pem

2. generate EC private key

        openssl pkcs8 -topk8 -inform pem -in ec-key.pem -outform pem \
            -nocrypt -out ec-key-1.pem

3. generate EC public key

        openssl ec -in ec-key-1.pem -pubout -out public.pem

Save both keys in a `private` folder (not under source control) and then point the relevant application configuration (`application.yaml`) to them:

```yaml
secrets:
  keypair:
    private: "private/ec-key-1.pem"
    pub: "private/ec-key-pub.pem"
```

You can use either an absolute path, or the relative path to the current directory from where you are launching the Web server.


## Supporting Services

The sample app (`jwt-vault`) uses the following services:

  - Mongo (users DB);
  - OPA Policy Server; and
  - Hashicorp Vault (key store).

Use the following to run the servers locally:

```
docker run --rm -d -p 27017:27017 --name mongodb mongo:3.7
docker run --rm -d -p 8181:8181 --name opa openpolicyagent/opa run --server
# TODO: Vault container
```

`TODO:` a full Kubernetes service/pod spec to run all services.

## Web Server (Demo app)

`TODO`

# OPA Policies

They are stored in `src/main/rego` and can be uploaded to the OPA policy server via a `curl POST` (see `REST API` in [Useful Links](useful-links#)); examples of policy evaulations are in `src/test/policies_tests` as JSON files; they can be executed against the policy server using the `/data` endpoint:


    POST http://localhost:8181/v1/data/kapsules/valid_token

    {
      "input": {
          "user": "myuser",
          "role": "USER",
          "token": "eyJ0eXAi....iCzY"
      }
    }



### Useful links

1. [REGO Playground](https://play.openpolicyagent.org/)
1. [OPA Server REST API for Data](https://www.openpolicyagent.org/docs/latest/rest-api/#data-api)
1. [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
1. [OPA - How does it work](https://www.openpolicyagent.org/docs/latest/philosophy/#how-does-opa-work)
1. [OPA Policy Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
1. [Docker Hub - OPA image](https://hub.docker.com/r/openpolicyagent/opa)
