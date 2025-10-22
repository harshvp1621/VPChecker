#!/bin/bash

ARANGO_USERNAME="root"
ARANGO_PASSWORD="root"

arangorestore \
    --server.endpoint tcp://127.0.0.1:8529 \
    --server.username $ARANGO_USERNAME \
    --server.password $ARANGO_PASSWORD \
    --server.database sysfilter \
    --input-directory ../../../artifact/db_dump/ \
    --create-database true \
    --include-system-collections true \
    --threads $(nproc)
