#!/bin/bash

cp ./requirements-local.txt ../docker

echo "Copy successful!"

cd ..

docker compose -f ./docker-compose-non-dev.yml -f ./plandoc-custom/docker-compose.override.yml up -d

docker network connect bi_net superset_app

