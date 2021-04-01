# JWT Authorization Policy
# Created M. Massenzio, 2020-11-22
#
# This should be loaded to the OPA Policy Server via a PUT request to the /v1/policies endpoint.

package kapsules

default allow = false

# The JWT carries the username and roles, which will be used
# to authorize access to the endpoint (`input.resource.path`)
# TODO: roles should be an array
token := t {
    t := io.jwt.decode(input.api_token)
}

user := u {
    some i
    token[i].iss == "demo-issuer"
    u = token[i].sub
}

roles := r {
    some i
    r = token[i].roles
}

# System administrators can modify all entities
is_sysadmin {
    some i
    roles[i] == "SYSTEM"
}

# Admin users can only create/modify a subset
# of entities
is_admin {
    some i
    roles[i] == "ADMIN"
}

# Users can only modify self, and entities associated
# with the users themselves.
is_user {
    some i
    roles[i] == "USER"
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
    is_sysadmin
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
