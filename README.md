# Usage example

## Generate users
`python keycloak_manager.py generate --count 50 --output users.csv`

## Create users
`python keycloak_manager.py create --csv users.csv --realm myrealm --client-id myclient --client-secret mysecret`

## Delete users
`python keycloak_manager.py delete --csv users.csv --realm myrealm --client-id myclient --client-secret mysecret`

## Using defaults from .env
`python keycloak_manager.py create --csv users.csv`

## Override specific values
`python keycloak_manager.py create --csv users.csv --realm custom-realm`