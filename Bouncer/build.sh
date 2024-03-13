#!/bin/bash

docker build -t bouncer-xapp .
docker image save bouncer-xapp -o bouncer-xapp.tar
sudo ctr -n k8s.io i import bouncer-xapp.tar
