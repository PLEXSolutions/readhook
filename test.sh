#!/bin/bash

docker run -it --rm --name readhook readhook /readhook/app/fullhook "$1"
