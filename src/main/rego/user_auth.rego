package kapsules

import data.kapsules.common

import input.user
import input.resource


# A user can view/modify self, but cannot create more users.
user_owns_self {
    allowed_methods := ["GET", "PUT", "DELETE"]
    common.entity == "users"
    common.entity_id == common.username
    allowed_methods[_] == resource.method
}


allow {
    user_owns_self
}
