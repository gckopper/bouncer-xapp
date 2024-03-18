#!/bin/bash

docker build -t bouncer-oai .
docker image save bouncer-oai -o bouncer-oai.tar
sudo ctr -n k8s.io i import bouncer-oai.tar
