#!/bin/bash

hostport="$1"

if [[ "$hostport" == "" ]]; then
	hostport="docker.for.mac.localhost:5555"
fi

docker run -it --rm --name readhook readhook /readhook/app/fullhook "$hostport"
