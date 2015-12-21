#!/bin/bash

docker kill gfbuild
docker rm gfbuild

docker build --tag "grafana/buildcontainer" docker/buildcontainer

docker run -i -t \
  -v $GOPATH:/go \
  --name gfbuild grafana/buildcontainer
