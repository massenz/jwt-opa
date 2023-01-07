# JWT Authorization Policy
# Created M. Massenzio, 2022-11-15
#
# This should be loaded to the OPA Policy Server via a PUT request to the /v1/policies endpoint.

package com.alertavert.userauth
import future.keywords.in

# The JWT carries the username and roles, which will be used
# to authorize access to the endpoint (`input.resource.path`)
token := t[1] {
    t := io.jwt.decode(input.api_token)
}

user := u {
    token.iss == "demo-issuer"
    u = token.sub
}

roles := r {
    r = token.roles
}

# SYSTEM roles (typically, only bots) are allowed to make any
# API calls, with whatever HTTP Method.
is_system {
    some i, "SYSTEM" in roles
}

# Admin users can only create/modify a subset
# of entities, but is still a powerful role, ASSIGN WITH CARE.
is_admin {
    some i, "ADMIN" in roles
}

# Users can only modify self, and entities associated
# with the users themselves.
# We assume that the user is valid if it could obtain a valid JWT and
# has at least one Role.
is_user {
    count(roles) > 0
}

split_path(path) = s {
    t := trim(path, "/")
    s := split(t, "/")
}

# Split the path segments into their constituents
segments = split_path(input.resource.path)
entity := segments[0]
entity_id := segments[1]

# System accounts are allowed to make all API calls.
allow {
    is_system
}

# User is allowed to view/modify self
# but cannot create/delete itself.
allow {
    allowed_methods := [ "GET", "PUT"]
    is_user
    entity == "users"
    entity_id == user
    input.resource.method == allowed_methods[_]
}

# Admin is allowed to create/delete users, but cannot view/modify.
allow {
    allowed_methods := [ "DELETE", "POST"]
    is_admin
    entity == "users"
    input.resource.method == allowed_methods[_]
}
