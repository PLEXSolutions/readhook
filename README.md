# redhook
Red-team tool to hook libc read syscall with a buffer overflow vulnerability.

## Building

The file `redhook.c` is intended to be included in something else, like a Dockerfile, by cloning it and building it for the particular environment. Use the following command line in the context of the OS in which you would like to hook the read syscall:
```
gcc -fPIC -shared -o redhook.so redhook.c -ldl
```
