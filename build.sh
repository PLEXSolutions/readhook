#!/bin/bash
docker build --no-cache -t readhook .

# Extract the library from the container
docker run -d --rm --name readhook readhook sleep 10
docker cp readhook:/readhook/dll/basehook.so $PWD/basehook.so
docker cp readhook:/readhook/dll/fullhook.so $PWD/fullhook.so
docker kill readhook
