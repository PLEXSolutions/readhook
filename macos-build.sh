#!/bin/bash
gcc -fPIC -shared -o redhook.so redhook.c -ldl
