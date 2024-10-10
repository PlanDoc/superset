#!/bin/bash

cd ..

docker compose -f ./docker-compose-non-dev.yml -f ./plandoc-custom/docker-compose.override.yml down
