#!/bin/bash

buildtarget()
{
	command="pv build -n redhook ${@:1} docker"
	echo $command
	$command
}

if [ "$1" == "jenkins" ]; then
	shift
	buildtarget -s -r polyverse
	buildtarget -s -r internal.hub.polyverse.io
else
	buildtarget "$@"
fi
