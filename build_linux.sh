#!/bin/bash

docker build . -t grafana-build:1
docker run -it \
  --rm \
  -v ${PWD}/bin:/data \
  grafana-build:1 \
  /bin/bash -c "cp -r ./bin/linux-amd64 /data/"
