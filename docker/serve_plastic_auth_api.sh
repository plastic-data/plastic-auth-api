#!/bin/bash

sed -e "s/mongodb_address = localhost/mongodb_address = ${MONGO_PORT_27017_TCP_ADDR}/" -e "s/mongodb_port = 27017/mongodb_port = ${MONGO_PORT_27017_TCP_PORT}/" /src/plastic-auth-api/production.ini > /src/plastic-auth-api/production-local.ini
chaussette --backend geventws4py --host 0.0.0.0 --port 2040 paste:/src/plastic-auth-api/production-local.ini
