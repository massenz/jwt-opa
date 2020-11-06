package kapsules

import kapsules.common

import input.user
import input.resource


# A user can view/modify self, but cannot create more users.
user_owns_self {
    allowed_methods := ["GET", "PUT", "DELETE"]
    entity == "users"
    entity_id == username
    allowed_methods[_] == resource.method
}


allow {
    user_owns_self
}
