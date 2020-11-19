# JWT Integration with OPA, Using Spring Security



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
