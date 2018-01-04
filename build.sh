#!/bin/bash
gcc -fPIC -shared -o redhook.so redhook.c -ldl
#gcc -fPIC -o redhook redhook.c
