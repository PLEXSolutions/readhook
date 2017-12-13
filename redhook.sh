#!/bin/bash
SHORT_DESCRIPTION="Test for LD_PRELOAD of redhook"

USAGE="$(cat <<EOF

Usage: sh redhook.sh ${0##*/}

$SHORT_DESCRIPTION

EOF
)"

if [ $# -ne 0 ]; then
  printf "$USAGE\n\n"
  exit 1
fi

# Use this command to run
docker run --rm --privileged --name redhook -p 8080:8080 -p 8008:8008 polyverse/redhook

# Use this command to debug (and run the server by hand internally, using gdb)
#docker run --rm --privileged --name redhook --entrypoint /bin/bash -it -p 8080:8080 -p 8008:8008 polyverse/redhook
