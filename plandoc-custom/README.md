# PlanDoc Keycloak Customization

This repository contains the customizations for the Keycloak server used by PlanDoc.

## Customizations

- A custom Keycloak security manager, which registers the user in the Superset database when they log in for the first
  time. The default role is 'customer', assigned to all users who don't have specific Keycloak roles. If the user has an
  assigned Keycloak role, the 'customer' role will be copied to the user's roles in the Superset database, then removed
  from their Keycloak roles. The user's roles will be updated each time they log in.
- Custom logo and favicon.
- Database password, secret key, and OIDC client secret are stored in secret files.
- Dashboard roles are enabled by default and displayed in the Dashboards table.

## Build

To build with the customizations, run the following command:

```./build.sh```

This will copy the requirements-list.txt file to the docker directory and run the docker-compose non dev build command
with the override file.

## Run

To run with the customizations, run the following command:

```./run.sh```

This will run the docker-compose up command with the override file.

## Stop

To stop, run the following command:

```./stop.sh```

This will run the docker-compose down command with the override file.

