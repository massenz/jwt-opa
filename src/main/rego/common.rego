package kapsules.common

import input.user
import input.resource

username = user.username

is_sysadmin {
    role := input.user.roles[_]
    role == "SYSTEM"
}

is_user {
    role := input.user.roles[_]
    role == "USER"
}

split_path(path) = s {
    t := trim(resource.path, "/")
    s := split(t, "/")
}

# Split the path segments into their constituents
segments = split_path(resource.path)
entity := segments[0]
entity_id := segments[1]

# System accounts are allowed to make all API calls.
allow {
    is_sysadmin
}
