#!/bin/bash
gcc -fPIC -shared -o redhook.so redhook.c -ldl
gcc -DREDHOOK_MAIN=1 -fPIC -o redhook redhook.c
