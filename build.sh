#!/bin/bash
# Delete the old artifacts
rm -r app dll

# Build readhook
docker build -t readhook .

# Run readhook and just sleep while we copy the build artifacts
docker run -d --rm --name readhook readhook sleep 60

# Extract the buld artifacts
docker cp readhook:/readhook/dll/ $PWD/dll/
docker cp readhook:/readhook/app/ $PWD/app/

# We're done so kill it since it's just sleeping
docker kill readhook
