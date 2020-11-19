package kapsules

default valid_token = false

tok := io.jwt.decode(input.token)
role := input.role

valid_token {
    some i
    input.user == tok[i].sub
    role == tok[i].role
    "covaxx" == tok[i].iss
}
