#!/bin/bash

HOST_AND_PORT="$1"

if [[ "$HOST_AND_PORT" == "" ]]; then
	HOST_AND_PORT="docker.for.mac.localhost:5555"
fi

docker run -it --rm --name readhook readhook /readhook/app/fullhook "$HOST_AND_PORT"
