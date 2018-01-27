#!/bin/bash
docker build --no-cache -t readhook .

# Extract the library from the container
docker run -d --rm --name readhook readhook sleep 10
docker cp readhook:/readhook/dll/makeload.so $PWD/makeload.so
docker cp readhook:/readhook/dll/readhook.so $PWD/readhook.so
docker kill readhook
